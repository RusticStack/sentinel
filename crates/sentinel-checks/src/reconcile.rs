//! Refreshes ask GitHub, never the webhook body, and commit under the row's seq fence so a stale pass cannot overwrite a newer schedule.
//! Nothing is revoked on a guess: only a 404 or a mismatched identity revokes a binding; other failures retry under back-off.
//! The lane never holds the writer while a request is on the wire.

use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

use sentinel_core::UnixMillis;
use sentinel_github::{
    app::{App, Installation, InstallationRepo, RepoState, Token},
    checks::repository_path,
};
use sentinel_store::{Error as StoreError, Store, github_events, sources_forge};

const TOKEN_MARGIN_MS: i64 = 120_000;
const MAX_CACHED_TOKENS: usize = 1024;

#[derive(Clone, Copy, Debug)]
pub struct Config {
    pub idle: Duration,
    pub min_backoff: Duration,
    pub max_backoff: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            idle: Duration::from_millis(250),
            min_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(30),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Notice {
    pub kind: i64,
    pub outcome: String,
}

pub struct Reconcile {
    stop: Arc<AtomicBool>,
    settled: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
    thread: Option<thread::JoinHandle<()>>,
}

impl Reconcile {
    pub fn start(
        store: Arc<Store>,
        app: Arc<App>,
        config: Config,
        notice: impl Fn(&Notice) + Send + Sync + 'static,
    ) -> Reconcile {
        let stop = Arc::new(AtomicBool::new(false));
        let settled = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        let thread = {
            let (stop, settled) = (Arc::clone(&stop), Arc::clone(&settled));
            thread::Builder::new()
                .name("sentinel-github-reconcile".into())
                .spawn(move || {
                    let mut worker = Worker {
                        store,
                        app,
                        tokens: HashMap::new(),
                    };
                    run(&mut worker, &config, &stop, &settled, &notice)
                })
                .expect("spawn github reconcile lane")
        };
        Reconcile {
            stop,
            settled,
            thread: Some(thread),
        }
    }
}

impl Drop for Reconcile {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let (lock, cv) = &*self.settled;
        *lock.lock().unwrap_or_else(|p| p.into_inner()) = true;
        cv.notify_all();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

struct Worker {
    store: Arc<Store>,
    app: Arc<App>,
    tokens: HashMap<u64, Token>,
}

fn run(
    worker: &mut Worker,
    config: &Config,
    stop: &AtomicBool,
    settled: &(std::sync::Mutex<bool>, std::sync::Condvar),
    notice: &dyn Fn(&Notice),
) {
    let mut failures: u32 = 0;
    while !stop.load(Ordering::Acquire) {
        let seeded = worker
            .store
            .writer()
            .write(|tx| github_events::seed(tx, UnixMillis::now()))
            .is_ok();
        if seeded {
            break;
        }
        failures = failures.saturating_add(1);
        wait(settled, backoff(config, failures));
    }
    while !stop.load(Ordering::Acquire) {
        let work = match worker
            .store
            .read(|c| github_events::due(c, UnixMillis::now()))
        {
            Ok(work) => work,
            Err(_) => {
                failures = failures.saturating_add(1);
                wait(settled, backoff(config, failures));
                continue;
            }
        };
        let Some(work) = work else {
            failures = 0;
            wait(settled, config.idle);
            continue;
        };
        let outcome = match work.kind {
            0 => worker.installation(&work),
            _ => worker.repository(&work),
        };
        let unrecorded = outcome == STORE;
        if unrecorded {
            failures = failures.saturating_add(1);
        } else {
            failures = 0;
        }
        notice(&Notice {
            kind: work.kind,
            outcome,
        });
        if unrecorded {
            wait(settled, backoff(config, failures));
        }
    }
}

const STORE: &str = "store";

enum TokenOutcome {
    Ready(Token),
    Gone,
    Refused,
    Retry,
}

impl Worker {
    fn token(&mut self, external: u64, now: UnixMillis) -> TokenOutcome {
        if let Some(cached) = self.tokens.get(&external)
            && cached.expires_ms > now.0 + TOKEN_MARGIN_MS
        {
            return TokenOutcome::Ready(Token {
                secret: cached.secret.clone(),
                expires_ms: cached.expires_ms,
            });
        }
        let installed = match self.app.installation_status(external, now.0) {
            Ok(Some(installed)) => installed,
            Ok(None) => return TokenOutcome::Gone,
            Err(_) => return TokenOutcome::Retry,
        };
        let token = match self.app.reconciliation_token(&installed, now.0) {
            Ok(token) => token,
            Err(sentinel_github::Error::Response("installation access refused")) => {
                return TokenOutcome::Refused;
            }
            Err(_) => return TokenOutcome::Retry,
        };
        self.tokens.retain(|_, t| t.expires_ms > now.0);
        if self.tokens.len() >= MAX_CACHED_TOKENS
            && !self.tokens.contains_key(&external)
            && let Some(oldest) = self
                .tokens
                .iter()
                .min_by_key(|(_, t)| t.expires_ms)
                .map(|(key, _)| *key)
        {
            self.tokens.remove(&oldest);
        }
        let secret = token.secret.clone();
        let expires_ms = token.expires_ms;
        self.tokens.insert(external, token);
        TokenOutcome::Ready(Token { secret, expires_ms })
    }

    fn settle(&self, work: &github_events::Refresh, retry: bool) -> &'static str {
        let work = *work;
        if self
            .store
            .writer()
            .write(move |tx| github_events::settled(tx, &work, UnixMillis::now(), retry))
            .is_err()
        {
            return "store";
        }
        if retry { "retry" } else { "settled" }
    }

    fn unreadable(&self, work: &github_events::Refresh, error: &StoreError) -> String {
        match error {
            StoreError::Corrupt(_) => self.settle(work, true).into(),
            _ => STORE.into(),
        }
    }

    fn finish(&self, work: &github_events::Refresh) -> &'static str {
        let work = *work;
        if self
            .store
            .writer()
            .write(move |tx| github_events::finished(tx, &work))
            .is_err()
        {
            return "store";
        }
        "target gone"
    }

    fn installation(&mut self, work: &github_events::Refresh) -> String {
        let target = match self
            .store
            .read(|c| github_events::install_target(c, &work.id))
        {
            Ok(Some(target)) => target,
            Ok(None) => return self.finish(work).into(),
            Err(error) => return self.unreadable(work, &error),
        };
        let mut installed = match self
            .app
            .installation_status(target.external, UnixMillis::now().0)
        {
            Ok(Some(installed)) => installed,
            Ok(None) => {
                let work = *work;
                let gone = self
                    .store
                    .writer()
                    .write(move |tx| github_events::installation_gone(tx, &work, &work.id))
                    .is_ok();
                return if gone {
                    "installation gone".into()
                } else {
                    "store".into()
                };
            }
            Err(_) => return self.settle(work, true).into(),
        };
        let revoked = if installed.suspended || !installed.permissions_valid {
            Vec::new()
        } else {
            match self.repositories(&installed, &work.id) {
                Ok(revoked) => revoked,
                Err(()) => return self.settle(work, true).into(),
            }
        };
        let snapshot = sources_forge::Snapshot {
            external_id: installed.id,
            account_id: installed.account_id,
            login: "",
            personal: installed.personal,
            suspended: installed.suspended,
            permissions_valid: installed.permissions_valid,
            expected: target.expected,
        };
        let login = std::mem::take(&mut installed.login);
        let (work, count) = (*work, revoked.len());
        match self.store.writer().write(move |tx| {
            github_events::apply_installation(
                tx,
                &work,
                sources_forge::Snapshot {
                    login: &login,
                    ..snapshot
                },
                &revoked,
                UnixMillis::now(),
            )
        }) {
            Ok(()) if count == 0 => "refreshed".into(),
            Ok(()) => format!("refreshed, {count} bindings revoked"),
            Err(_) => self.settle(&work, true).into(),
        }
    }

    fn repositories(
        &mut self,
        installed: &Installation,
        installation_row: &[u8; 16],
    ) -> Result<Vec<(sentinel_core::RepoId, i64)>, ()> {
        let bound = self
            .store
            .read(|c| github_events::bound_repositories(c, installation_row))
            .map_err(|_| ())?;
        let token = self
            .app
            .reconciliation_token(installed, UnixMillis::now().0)
            .map_err(|_| ())?;
        let list = self.app.installation_repositories(&token).map_err(|_| ())?;
        let observed: HashMap<u64, &InstallationRepo> =
            list.repos.iter().map(|repo| (repo.id, repo)).collect();
        let mut revoked = Vec::new();
        for (repo, forge_id, remote, version) in bound {
            match observed.get(&forge_id) {
                Some(seen) => {
                    let approved = repository_path(&remote)
                        .map(|(owner, name)| seen.full_name == format!("{owner}/{name}"))
                        .unwrap_or(false);
                    if !approved || seen.archived {
                        revoked.push((repo, version));
                    }
                }
                None if !list.truncated => revoked.push((repo, version)),
                None => {}
            }
        }
        Ok(revoked)
    }

    fn repository(&mut self, work: &github_events::Refresh) -> String {
        let target = match self.store.read(|c| github_events::repo_target(c, &work.id)) {
            Ok(Some(target)) => target,
            Ok(None) => return self.finish(work).into(),
            Err(error) => return self.unreadable(work, &error),
        };
        let token = match self.token(target.installation_external, UnixMillis::now()) {
            TokenOutcome::Ready(token) => token,
            TokenOutcome::Gone => {
                let (work, installation) = (*work, target.installation);
                let gone = self
                    .store
                    .writer()
                    .write(move |tx| github_events::installation_gone(tx, &work, &installation))
                    .is_ok();
                return if gone {
                    "installation gone".into()
                } else {
                    "store".into()
                };
            }
            TokenOutcome::Refused => {
                let (work, installation) = (*work, target.installation);
                let scheduled = self
                    .store
                    .writer()
                    .write(move |tx| {
                        github_events::schedule(tx, &installation, 0, UnixMillis::now())?;
                        github_events::settled(tx, &work, UnixMillis::now(), false)
                    })
                    .is_ok();
                return if scheduled {
                    "installation refresh scheduled".into()
                } else {
                    "store".into()
                };
            }
            TokenOutcome::Retry => return self.settle(work, true).into(),
        };
        match self
            .app
            .repository_state(&token, target.forge_repo, &target.remote, target.account)
        {
            Ok(RepoState::Verified) => {
                let (work, repo, version) = (*work, target.repo, target.version);
                if self
                    .store
                    .writer()
                    .write(move |tx| {
                        github_events::apply_repository(
                            tx,
                            &work,
                            repo,
                            version,
                            false,
                            UnixMillis::now(),
                        )
                    })
                    .is_err()
                {
                    return "store".into();
                }
                "verified".into()
            }
            Ok(state) => {
                let (work, repo, version) = (*work, target.repo, target.version);
                if self
                    .store
                    .writer()
                    .write(move |tx| {
                        github_events::apply_repository(
                            tx,
                            &work,
                            repo,
                            version,
                            true,
                            UnixMillis::now(),
                        )
                    })
                    .is_err()
                {
                    return "store".into();
                }
                match state {
                    RepoState::Changed => "binding revoked: changed".into(),
                    _ => "binding revoked: gone".into(),
                }
            }
            Err(sentinel_github::Error::Response("token refused")) => {
                self.tokens.remove(&target.installation_external);
                self.settle(work, true).into()
            }
            Err(_) => self.settle(work, true).into(),
        }
    }
}

fn backoff(config: &Config, failures: u32) -> Duration {
    config
        .min_backoff
        .saturating_mul(1u32 << failures.min(5))
        .min(config.max_backoff)
}

fn wait(settled: &(std::sync::Mutex<bool>, std::sync::Condvar), timeout: Duration) {
    let (lock, cv) = settled;
    let settled = lock.lock().unwrap_or_else(|p| p.into_inner());
    if *settled {
        return;
    }
    let (mut settled, _) = cv
        .wait_timeout(settled, timeout)
        .unwrap_or_else(|p| p.into_inner());
    *settled = false;
}
