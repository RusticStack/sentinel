//! Opt-in bounded ref polling (G07).
//!
//! One thread watches `poll_configs` for repositories whose poll has come
//! due, asks the remote for its heads and tags through `git ls-remote`
//! (bounded by duration, output size and ref count), and admits every
//! observed transition as an ordinary `poll`-provider delivery through the
//! same `intake::accept` a hook uses — validation, dedup, resolution and
//! dispatch are then G02/G03's own path, unchanged.
//!
//! Polling is not a delivery guarantee: an advertisement is a point-in-time
//! snapshot, so an intermediate push can be missed between polls, and the
//! first successful poll only establishes the baseline. Events remain the
//! low-latency path; this exists so repositories without a forge's delivery
//! mechanism still get observed. The cursor and the delivery it produced
//! commit in one transaction, so a restart can neither skip a change nor
//! replay one.

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
use sentinel_github::app::App;
use sentinel_protocol::source::{Access, ref_matches};
use sentinel_store::{Error as StoreError, Store, poll};

use crate::source;

/// What the poller asks of a remote, injectable for tests.
pub trait Lister: Send + Sync {
    /// Advertise `request.remote`'s heads and tags within its budgets.
    fn refs(
        &self,
        request: &ListRequest<'_>,
    ) -> Result<Vec<sentinel_git::RefTip>, sentinel_git::Error>;
}

/// One bounded `ls-remote` call's inputs.
pub struct ListRequest<'a> {
    /// Scratch directory for credential helpers.
    pub dir: &'a Path,
    pub remote: &'a str,
    pub access: Option<&'a Access>,
    pub max_refs: usize,
    pub budget: Duration,
}

/// The production lister: `sentinel_git::ls_remote`.
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

/// How the poller paces itself. Defaults: eight repositories per pass, a
/// 250 ms idle tick, store back-off from one to thirty seconds, a 20-second
/// ls-remote budget, at most 4096 advertised refs, and failure back-off
/// capped at fifteen minutes.
#[derive(Clone, Copy, Debug)]
pub struct Config {
    pub batch: u16,
    pub idle: Duration,
    pub min_backoff: Duration,
    pub max_backoff: Duration,
    /// One `ls-remote` may not run longer than this; its process group is
    /// killed past the deadline.
    pub timeout: Duration,
    /// Advertised refs above this refuse the advertisement.
    pub max_refs: usize,
    /// Remote/backoff ceiling for a repository whose polls keep failing.
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

/// One repository's poll outcome, for the caller's diagnostics.
#[derive(Clone, Debug)]
pub struct Notice {
    pub repo: RepoId,
    pub outcome: String,
    /// The poll itself failed; schedules back off rather than spinning.
    pub failed: bool,
}

/// A running poller; dropping it stops and joins the thread.
pub struct Poll {
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

struct Inner {
    store: Arc<Store>,
    key: Option<Arc<Key>>,
    app: Option<Arc<App>>,
    destinations: Arc<[String]>,
    lister: Arc<dyn Lister>,
    work_root: PathBuf,
    config: Config,
    notice: Box<dyn Fn(&Notice) + Send + Sync>,
}

impl Poll {
    /// Start the poll lane. `work_root` holds per-repository scratch space
    /// for credential helpers; stale leftovers from a previous run are
    /// removed before the first pass.
    #[allow(clippy::too_many_arguments)]
    pub fn start(
        store: Arc<Store>,
        key: Option<Arc<Key>>,
        app: Option<Arc<App>>,
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
            app,
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
            // A panic in one pass (a bug, never an input it was meant to
            // handle) costs that pass and a back-off, not polling for every
            // repository until the controller restarts.
            let pass = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.pass()))
                .unwrap_or(Err(StoreError::WriterPanicked));
            match pass {
                Ok(worked) => {
                    backoff = self.config.min_backoff;
                    // More repositories may be due behind the batch cap; an
                    // idle pass sleeps until the next due poll.
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

    /// Wait in bounded slices so shutdown is never more than 50 ms away.
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

    /// Poll every repository whose schedule has come due. `true` when any
    /// work ran. A repository whose poll hits a store fault is rescheduled
    /// under its own failure back-off and the pass continues, so no one
    /// configuration can stay first in every pass and starve the rest.
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
        // What the binding authorizes right now. A configuration that
        // outlived its binding can never succeed again, so it is dropped
        // rather than retried forever; a suspended tenant or installation
        // may come back, so that one backs off and keeps its configuration.
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
            self.app.as_ref(),
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

        // Only the configured selection becomes observable state; everything
        // else the remote advertised is ignored.
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

    /// Record a poll failure: bounded exponential back-off from the
    /// configured interval, never below it.
    fn fail(&self, config: &poll::Config, reason: &str) -> Result<Notice, StoreError> {
        let repo = config.repo;
        let failures = config.failures + 1;
        let backoff = (config.interval_ms << failures.min(6) as u32)
            .min(self.config.max_failure_backoff_ms)
            .max(config.interval_ms);
        // Bounded on a character boundary: the reason can carry a remote's
        // stderr, and a byte cut through a multibyte character would panic.
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

/// The longest prefix of `text` that is at most `max` bytes and ends on a
/// character boundary.
fn truncate_chars(text: &str, max: usize) -> &str {
    &text[..text.floor_char_boundary(max)]
}

/// A stable per-repository offset, up to a quarter of the interval, so a
/// fleet of repositories configured together does not poll in lockstep —
/// including after a restart, since the offset derives from the id itself.
fn jitter(repo: RepoId, interval_ms: i64) -> i64 {
    let spread = (interval_ms / 4).max(1) as u64;
    let bytes: [u8; 8] = repo.as_bytes()[..8].try_into().unwrap_or_default();
    (u64::from_le_bytes(bytes) % spread) as i64
}
