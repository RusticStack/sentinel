//! The cursor and the delivery it produced commit in one transaction, so a restart neither skips nor replays a change.

use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

use sentinel_auth::sealed::Key;
use sentinel_core::{RepoId, UnixMillis};
use sentinel_github::app::Current;
use sentinel_protocol::source::{Access, ref_matches};
use sentinel_store::{Error as StoreError, Store, poll};

use crate::source;

pub trait Lister: Send + Sync {
    fn refs(
        &self,
        request: &ListRequest<'_>,
    ) -> Result<Vec<sentinel_git::RefTip>, sentinel_git::Error>;
}

pub struct ListRequest<'a> {
    pub dir: &'a Path,
    pub remote: &'a str,
    pub access: Option<&'a Access>,
    pub max_refs: usize,
    pub budget: Duration,
}

pub struct GitLister;

impl Lister for GitLister {
    fn refs(
        &self,
        request: &ListRequest<'_>,
    ) -> Result<Vec<sentinel_git::RefTip>, sentinel_git::Error> {
        sentinel_git::ls_remote(
            request.dir,
            request.remote,
            request.access,
            request.max_refs,
            request.budget,
        )
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Config {
    pub batch: u16,
    pub idle: Duration,
    pub min_backoff: Duration,
    pub max_backoff: Duration,
    pub timeout: Duration,
    pub max_refs: usize,
    pub max_failure_backoff_ms: i64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            batch: 8,
            idle: Duration::from_millis(250),
            min_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(30),
            timeout: Duration::from_secs(20),
            max_refs: 4096,
            max_failure_backoff_ms: 15 * 60 * 1_000,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Notice {
    pub repo: RepoId,
    pub outcome: String,
    pub failed: bool,
}

pub struct Poll {
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

struct Inner {
    store: Arc<Store>,
    key: Option<Arc<Key>>,
    app: Current,
    destinations: Arc<[String]>,
    lister: Arc<dyn Lister>,
    work_root: PathBuf,
    config: Config,
    notice: Box<dyn Fn(&Notice) + Send + Sync>,
}

impl Poll {
    #[allow(clippy::too_many_arguments)]
    pub fn start(
        store: Arc<Store>,
        key: Option<Arc<Key>>,
        app: impl Into<Current>,
        destinations: Arc<[String]>,
        lister: Arc<dyn Lister>,
        work_root: PathBuf,
        config: Config,
        notice: impl Fn(&Notice) + Send + Sync + 'static,
    ) -> std::io::Result<Poll> {
        fs::create_dir_all(&work_root)?;
        if let Ok(entries) = fs::read_dir(&work_root) {
            for entry in entries.flatten() {
                let _ = fs::remove_dir_all(entry.path());
            }
        }
        let inner = Arc::new(Inner {
            store,
            key,
            app: app.into(),
            destinations,
            lister,
            work_root,
            config,
            notice: Box::new(notice),
        });
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let thread = thread::Builder::new()
            .name("sentinel-poll".into())
            .spawn(move || inner.run(&flag))?;
        Ok(Poll {
            stop,
            thread: Some(thread),
        })
    }
}

impl Drop for Poll {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Inner {
    fn run(&self, stop: &AtomicBool) {
        let mut backoff = self.config.min_backoff;
        while !stop.load(Ordering::Acquire) {
            let pass = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.pass()))
                .unwrap_or(Err(StoreError::WriterPanicked));
            match pass {
                Ok(worked) => {
                    backoff = self.config.min_backoff;
                    if !worked {
                        self.wait(stop, self.config.idle);
                    }
                }
                Err(_) => {
                    self.wait(stop, backoff);
                    backoff = (backoff * 2).min(self.config.max_backoff);
                }
            }
        }
    }

    fn wait(&self, stop: &AtomicBool, duration: Duration) {
        let deadline = std::time::Instant::now() + duration;
        loop {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() || stop.load(Ordering::Acquire) {
                return;
            }
            thread::sleep(left.min(Duration::from_millis(50)));
        }
    }

    fn pass(&self) -> Result<bool, StoreError> {
        let now = UnixMillis::now();
        let due = self
            .store
            .read(|conn| poll::due(conn, now, self.config.batch))?;
        let worked = !due.is_empty();
        for config in &due {
            let notice = match self.poll_one(config) {
                Ok(notice) => notice,
                Err(error) => self.fail(config, &format!("store: {error}"))?,
            };
            (self.notice)(&notice);
        }
        Ok(worked)
    }

    fn poll_one(&self, config: &poll::Config) -> Result<Notice, StoreError> {
        let repo = config.repo;
        // Revoked bindings drop their config; suspended ones back off because they may return.
        let binding = match source::classify(&self.store, repo)? {
            source::Lookup::Bound(binding) => binding,
            source::Lookup::Unbound | source::Lookup::Unusable("binding_revoked") => {
                self.store
                    .writer()
                    .write(move |tx| poll::drop_config(tx, repo))?;
                return Ok(Notice {
                    repo,
                    outcome: "unbound".into(),
                    failed: false,
                });
            }
            source::Lookup::Unusable(reason) => return self.fail(config, reason),
        };
        if !source::destination_allowed(&self.destinations, &binding.metadata.binding.remote) {
            return self.fail(config, "destination_refused");
        }

        let now = UnixMillis::now();
        let access = match source::issue(
            &self.store,
            self.key.as_deref(),
            self.app.get(),
            &binding,
            now,
        ) {
            Ok(access) => access,
            Err(error) => return self.fail(config, &error.to_string()),
        };

        let dir = self.work_root.join(repo.to_string());
        let tips = self.lister.refs(&ListRequest {
            dir: &dir,
            remote: &access.binding.remote,
            access: Some(&access),
            max_refs: self.config.max_refs,
            budget: self.config.timeout,
        });
        let tips = match tips {
            Ok(tips) => tips,
            Err(error) => return self.fail(config, &error.to_string()),
        };

        let mut seen = HashSet::with_capacity(tips.len());
        let tips: Vec<poll::Tip> = tips
            .into_iter()
            .filter(|tip| config.refs.iter().any(|p| ref_matches(p, &tip.name)))
            .filter(|tip| seen.insert(tip.name.clone()))
            .map(|tip| poll::Tip {
                name: tip.name,
                oid: tip.oid,
                peeled: tip.peeled,
            })
            .collect();

        let interval_ms = config.interval_ms;
        let admitted = self.store.writer().write(move |tx| {
            let now = UnixMillis::now();
            let admitted = poll::admit(tx, repo, &tips, now)?;
            let next = now.0 + interval_ms + jitter(repo, interval_ms);
            poll::schedule(tx, repo, next, 0, None, now)?;
            Ok(admitted)
        })?;
        let outcome = match admitted {
            None => "disabled".to_owned(),
            Some(a) if a.baseline > 0 => format!("baseline:{}", a.baseline),
            Some(a) => {
                let mut parts = Vec::with_capacity(4);
                if a.created > 0 {
                    parts.push(format!("created:{}", a.created));
                }
                if a.moved > 0 {
                    parts.push(format!("moved:{}", a.moved));
                }
                if a.deleted > 0 {
                    parts.push(format!("deleted:{}", a.deleted));
                }
                if a.deferred > 0 {
                    parts.push(format!("deferred:{}", a.deferred));
                }
                if parts.is_empty() {
                    "unchanged".to_owned()
                } else {
                    parts.join(",")
                }
            }
        };
        Ok(Notice {
            repo,
            outcome,
            failed: false,
        })
    }

    fn fail(&self, config: &poll::Config, reason: &str) -> Result<Notice, StoreError> {
        let repo = config.repo;
        let failures = config.failures + 1;
        let backoff = (config.interval_ms << failures.min(6) as u32)
            .min(self.config.max_failure_backoff_ms)
            .max(config.interval_ms);
        // A byte cut through a multibyte character would panic, so truncate on a char boundary.
        let reason = truncate_chars(reason, 256).to_owned();
        let stored = reason.clone();
        self.store.writer().write(move |tx| {
            let now = UnixMillis::now();
            poll::schedule(tx, repo, now.0 + backoff, failures, Some(&stored), now)
        })?;
        Ok(Notice {
            repo,
            outcome: format!("failed:{reason}"),
            failed: true,
        })
    }
}

fn truncate_chars(text: &str, max: usize) -> &str {
    &text[..text.floor_char_boundary(max)]
}

fn jitter(repo: RepoId, interval_ms: i64) -> i64 {
    let spread = (interval_ms / 4).max(1) as u64;
    let bytes: [u8; 8] = repo.as_bytes()[..8].try_into().unwrap_or_default();
    (u64::from_le_bytes(bytes) % spread) as i64
}
