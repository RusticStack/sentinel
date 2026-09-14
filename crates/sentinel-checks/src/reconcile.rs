//! The lifecycle reconcile lane (G05).
//!
//! `github_refresh` rows are the durable hint list: a signed webhook asked
//! for a refresh, or the periodic pass owes one. The lane asks GitHub — never
//! the webhook body — and commits the answer under the row's `seq` fence, so
//! a stale pass can never overwrite a newer schedule.
//!
//! An installation row (kind 0) applies the authenticated snapshot through
//! `sources_forge::refresh` — suspension, permission loss and account
//! transfer all land there — then reconciles the bound repository set against
//! the installation's actual list: a repository no longer granted, renamed,
//! transferred or archived loses its binding. A repository row (kind 1)
//! verifies one binding's remote identity the same way. Nothing is revoked on
//! a guess: only a 404 or a mismatched identity does it; every other failure
//! retries under bounded back-off.
//!
//! The lane never holds the writer while a request is on the wire. It reads
//! what the call needs, talks to GitHub, then commits in a short transaction.

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
use sentinel_store::{Store, github_events, sources_forge};

/// How long before expiry a cached reconciliation token is replaced.
const TOKEN_MARGIN_MS: i64 = 120_000;
/// One cached token per installation; bounded like the publisher's cache.
const MAX_CACHED_TOKENS: usize = 1024;

/// How the lane paces itself: a 250 ms idle tick and store-failure back-off
/// from one second to thirty.
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

/// One pass's outcome, for the caller's diagnostics.
#[derive(Clone, Debug)]
pub struct Notice {
    /// 0 for an installation pass, 1 for a repository pass.
    pub kind: i64,
    pub outcome: String,
}

/// A running lane; dropping it stops and joins the thread.
pub struct Reconcile {
    stop: Arc<AtomicBool>,
    settled: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
    thread: Option<thread::JoinHandle<()>>,
}

impl Reconcile {
    /// Start the lane. Seeding is part of startup: every known installation
    /// and bound repository owes a periodic pass, and a row scheduled while
    /// the lane was down is simply due.
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
    /// One reconciliation token per installation external id.
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
    // Seeding is retried until it lands: without it, installations and
    // bindings that predate this start would never owe a periodic pass.
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
        failures = 0;
        notice(&Notice {
            kind: work.kind,
            outcome,
        });
    }
}

/// What minting a reconciliation token resolved to.
enum TokenOutcome {
    Ready(Token),
    /// A verified 404: the installation is gone for good.
    Gone,
    /// Suspended or permission-invalid: the kind-0 pass repairs it.
    Refused,
    /// Transient: try again.
    Retry,
}

impl Worker {
    /// A reconciliation token for the installation, cached until close to
    /// expiry. The installation snapshot is fetched on a miss — the same read
    /// that decides whether minting is allowed at all.
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

    /// Park the row after a transient failure (`retry=true`, bounded
    /// back-off) or for the next periodic pass (`false`).
    fn settle(&self, work: &github_events::Refresh, retry: bool) -> &'static str {
        let work = *work;
        let _ = self
            .store
            .writer()
            .write(move |tx| github_events::settled(tx, &work, UnixMillis::now(), retry));
        if retry { "retry" } else { "settled" }
    }

    /// The row's target vanished; drop it, fenced by the read sequence.
    fn finish(&self, work: &github_events::Refresh) -> &'static str {
        let work = *work;
        let _ = self
            .store
            .writer()
            .write(move |tx| github_events::finished(tx, &work));
        "target gone"
    }

    /// Kind 0: an authenticated installation snapshot plus the repository-set
    /// reconcile when the installation is usable.
    fn installation(&mut self, work: &github_events::Refresh) -> String {
        let target = match self
            .store
            .read(|c| github_events::install_target(c, &work.id))
        {
            Ok(Some(target)) => target,
            Ok(None) => return self.finish(work).into(),
            Err(_) => return "store".into(),
        };
        let mut installed = match self
            .app
            .installation_status(target.external, UnixMillis::now().0)
        {
            Ok(Some(installed)) => installed,
            Ok(None) => {
                let work = *work;
                let _ = self
                    .store
                    .writer()
                    .write(move |tx| github_events::installation_gone(tx, &work, &work.id));
                return "installation gone".into();
            }
            Err(_) => return self.settle(work, true).into(),
        };
        // The repository list is only fetched — and only proves anything —
        // while the installation can actually grant access.
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
            // A newer lifecycle landed while the request was out: retry.
            Err(_) => self.settle(&work, true).into(),
        }
    }

    /// The bindings GitHub no longer grants or names differently. `Err(())`
    /// is transient: the caller parks the row under retry back-off.
    fn repositories(
        &mut self,
        installed: &Installation,
        installation_row: &[u8; 16],
    ) -> Result<Vec<sentinel_core::RepoId>, ()> {
        let token = self
            .app
            .reconciliation_token(installed, UnixMillis::now().0)
            .map_err(|_| ())?;
        let list = self.app.installation_repositories(&token).map_err(|_| ())?;
        let bound = self
            .store
            .read(|c| github_events::bound_repositories(c, installation_row))
            .map_err(|_| ())?;
        let observed: HashMap<u64, &InstallationRepo> =
            list.repos.iter().map(|repo| (repo.id, repo)).collect();
        let mut revoked = Vec::new();
        for (repo, forge_id, remote) in bound {
            match observed.get(&forge_id) {
                // An approved remote never follows a rename, transfer or
                // archival: only an exact `owner/name` match stays bound.
                Some(seen) => {
                    let approved = repository_path(&remote)
                        .map(|(owner, name)| seen.full_name == format!("{owner}/{name}"))
                        .unwrap_or(false);
                    if !approved || seen.archived {
                        revoked.push(repo);
                    }
                }
                // A truncated list proves membership, never absence.
                None if !list.truncated => revoked.push(repo),
                None => {}
            }
        }
        Ok(revoked)
    }

    /// Kind 1: one bound repository's identity against the live API answer.
    fn repository(&mut self, work: &github_events::Refresh) -> String {
        let target = match self.store.read(|c| github_events::repo_target(c, &work.id)) {
            Ok(Some(target)) => target,
            // The binding was revoked or never existed: nothing to verify.
            Ok(None) => return self.finish(work).into(),
            Err(_) => return "store".into(),
        };
        let token = match self.token(target.installation_external, UnixMillis::now()) {
            TokenOutcome::Ready(token) => token,
            TokenOutcome::Gone => {
                let (work, installation) = (*work, target.installation);
                let _ = self
                    .store
                    .writer()
                    .write(move |tx| github_events::installation_gone(tx, &work, &installation));
                return "installation gone".into();
            }
            TokenOutcome::Refused => {
                // The installation row needs the kind-0 pass; it owns the
                // suspended/permissions state this token mint just proved.
                let (work, installation) = (*work, target.installation);
                let _ = self.store.writer().write(move |tx| {
                    github_events::schedule(tx, &installation, 0, UnixMillis::now())?;
                    github_events::settled(tx, &work, UnixMillis::now(), false)
                });
                return "installation refresh scheduled".into();
            }
            TokenOutcome::Retry => return self.settle(work, true).into(),
        };
        match self
            .app
            .repository_state(&token, target.forge_repo, &target.remote, target.account)
        {
            Ok(RepoState::Verified) => {
                let (work, repo) = (*work, target.repo);
                let _ = self.store.writer().write(move |tx| {
                    github_events::apply_repository(tx, &work, repo, false, UnixMillis::now())
                });
                "verified".into()
            }
            Ok(state) => {
                let (work, repo) = (*work, target.repo);
                let _ = self.store.writer().write(move |tx| {
                    github_events::apply_repository(tx, &work, repo, true, UnixMillis::now())
                });
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

/// Wait until the timeout, or until the lane is asked to stop.
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
