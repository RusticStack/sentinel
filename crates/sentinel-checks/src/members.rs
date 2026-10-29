//! Only verified answers change membership: a 404 counts as absent only after the organization identity is confirmed again.
//! Unknown answers keep existing access until the grace period expires and grant nothing new.
//! The lane never holds the writer while a request is on the wire.

use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use sentinel_core::UnixMillis;
use sentinel_github::{
    app::{Answer, App, OrgRole, Token},
    checks::repository_path,
};
use sentinel_store::{
    Store,
    github_members::{self, Check, Membership, Observed, RepoAccess, Target, Timing},
};

const TOKEN_MARGIN_MS: i64 = 120_000;
const MAX_CACHED: usize = 1024;
const MAX_PAUSE_MS: i64 = 60 * 60 * 1000;
/// The shortest gap between two reads of the queue: a commit wakes an idle lane, but a busy store must not
/// turn that into a read per commit.
const COMMIT_GAP: Duration = Duration::from_millis(250);

#[derive(Clone, Copy, Debug)]
pub struct Config {
    /// The longest an idle lane sleeps. It wakes earlier for a commit or when the next row falls due, so this
    /// is only the net for a write the commit notifier cannot see.
    pub idle: Duration,
    pub min_backoff: Duration,
    pub max_backoff: Duration,
    pub timing: Timing,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            idle: Duration::from_secs(2),
            min_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(30),
            timing: Timing {
                recheck_ms: DEFAULT_RECHECK_MS,
                grace_ms: DEFAULT_GRACE_MS,
            },
        }
    }
}

pub const DEFAULT_RECHECK_MS: i64 = 60 * 60 * 1000;
pub const DEFAULT_GRACE_MS: i64 = 24 * 60 * 60 * 1000;

#[derive(Clone, Debug)]
pub struct Notice {
    pub outcome: String,
}

pub struct Members {
    store: Arc<Store>,
    stop: Arc<AtomicBool>,
    settled: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
    thread: Option<thread::JoinHandle<()>>,
}

impl Members {
    pub fn start(
        store: Arc<Store>,
        app: Arc<App>,
        config: Config,
        notice: impl Fn(&Notice) + Send + Sync + 'static,
    ) -> Members {
        let stop = Arc::new(AtomicBool::new(false));
        let settled = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        let handle = Arc::clone(&store);
        let thread = {
            let (stop, settled) = (Arc::clone(&stop), Arc::clone(&settled));
            thread::Builder::new()
                .name("sentinel-github-members".into())
                .spawn(move || {
                    let mut worker = Worker {
                        store,
                        app,
                        sessions: HashMap::new(),
                        paused: HashMap::new(),
                    };
                    run(&mut worker, &config, &stop, &settled, &notice)
                })
                .expect("spawn github members lane")
        };
        Members {
            store: handle,
            stop,
            settled,
            thread: Some(thread),
        }
    }
}

impl Drop for Members {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let (lock, cv) = &*self.settled;
        *lock.lock().unwrap_or_else(|p| p.into_inner()) = true;
        cv.notify_all();
        self.store.changes().nudge();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

struct Session {
    token: Token,
    org_login: String,
    org_id: u64,
}

struct Worker {
    store: Arc<Store>,
    app: Arc<App>,
    sessions: HashMap<u64, Session>,
    paused: HashMap<u64, i64>,
}

const STORE: &str = "store";

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
            .write(|tx| github_members::seed(tx, UnixMillis::now()))
            .is_ok();
        if seeded {
            break;
        }
        failures = failures.saturating_add(1);
        wait(settled, backoff(config, failures));
    }
    loop {
        // Read before the stop flag: a drop that lands in between has already moved the generation.
        let seen = worker.store.changes().generation();
        if stop.load(Ordering::Acquire) {
            break;
        }
        let polled = Instant::now();
        let due = match worker
            .store
            .read(|c| github_members::due(c, UnixMillis::now()))
        {
            Ok(due) => due,
            Err(_) => {
                failures = failures.saturating_add(1);
                wait(settled, backoff(config, failures));
                continue;
            }
        };
        let Some(check) = due else {
            failures = 0;
            sleep_until_work(&worker.store, config, settled, seen, polled);
            continue;
        };
        let outcome = worker.pass(&check, config.timing);
        let unrecorded = outcome == STORE;
        failures = if unrecorded {
            failures.saturating_add(1)
        } else {
            0
        };
        notice(&Notice { outcome });
        if unrecorded {
            wait(settled, backoff(config, failures));
        }
    }
}

impl Worker {
    fn pass(&mut self, check: &Check, timing: Timing) -> String {
        let target = match self.store.read(|c| github_members::target(c, check)) {
            Ok(Some(target)) => target,
            Ok(None) => {
                let (check, now) = (*check, UnixMillis::now());
                return match self
                    .store
                    .writer()
                    .write(move |tx| github_members::no_target(tx, &check, timing, now))
                {
                    Ok(outcome) => outcome.into(),
                    Err(_) => STORE.into(),
                };
            }
            // The stored target of this pair cannot be read (a damaged binding, a malformed id). That says
            // nothing about the person, so access is left as it is and the row only waits, instead of
            // sitting at the head of the queue and holding back every other tenant's check.
            Err(error) if error.is_row_specific() => {
                let (check, now) = (*check, UnixMillis::now());
                return match self
                    .store
                    .writer()
                    .write(move |tx| github_members::park(tx, &check, now))
                {
                    Ok(outcome) => outcome.into(),
                    Err(_) => STORE.into(),
                };
            }
            Err(_) => return STORE.into(),
        };
        let now = UnixMillis::now();
        let observed = match self.observe(&target, now) {
            Ok(observed) => observed,
            Err(retry_after_ms) => return self.unreachable(check, timing, retry_after_ms),
        };
        let (check, more) = (*check, target.more);
        match self
            .store
            .writer()
            .write(move |tx| github_members::apply(tx, &check, more, &observed, timing, now))
        {
            Ok(outcome) => outcome.into(),
            Err(_) => STORE.into(),
        }
    }

    fn unreachable(
        &mut self,
        check: &Check,
        timing: Timing,
        retry_after_ms: Option<i64>,
    ) -> String {
        let (check, now) = (*check, UnixMillis::now());
        match self
            .store
            .writer()
            .write(move |tx| github_members::unreachable(tx, &check, timing, now, retry_after_ms))
        {
            Ok(outcome) => outcome.into(),
            Err(_) => STORE.into(),
        }
    }

    fn observe(&mut self, target: &Target, now: UnixMillis) -> Result<Observed, Option<i64>> {
        let Some(github_id) = target.github_id else {
            return Ok(Observed {
                github_id: None,
                membership: Membership::Unknown,
                repos: Vec::new(),
                complete: true,
            });
        };
        if target.unusable {
            return Err(None);
        }
        if let Some(until) = self.paused.get(&target.installation).copied() {
            if until > now.0 {
                return Err(Some(until - now.0));
            }
            self.paused.remove(&target.installation);
        }
        let app = Arc::clone(&self.app);
        let outcome = self.ask(&app, target, github_id, now);
        if let Err(Some(wait_ms)) = outcome {
            self.paused.insert(
                target.installation,
                now.0.saturating_add(wait_ms.min(MAX_PAUSE_MS)),
            );
        }
        outcome
    }

    fn ask(
        &mut self,
        app: &App,
        target: &Target,
        github_id: u64,
        now: UnixMillis,
    ) -> Result<Observed, Option<i64>> {
        let session = self.session(app, target, now)?;
        let login = match app.user_login(&session.token, github_id) {
            Answer::Known(login) => login,
            Answer::Absent => {
                return Ok(Observed {
                    github_id: Some(github_id),
                    membership: Membership::Absent,
                    repos: Vec::new(),
                    complete: true,
                });
            }
            Answer::Unknown { retry_after_s } => return Err(retry_after_s.map(|s| s * 1000)),
        };
        let role = match app.org_membership(
            &session.token,
            &session.org_login,
            session.org_id,
            github_id,
            &login,
        ) {
            Answer::Known(role) => role,
            Answer::Absent => {
                return self.confirm_absent(app, target, github_id, now);
            }
            Answer::Unknown { retry_after_s } => return Err(retry_after_s.map(|s| s * 1000)),
        };
        let mut observed = Observed {
            github_id: Some(github_id),
            membership: Membership::Active(match role {
                OrgRole::Owner => github_members::OrgRole::Owner,
                OrgRole::Member => github_members::OrgRole::Member,
            }),
            repos: Vec::new(),
            complete: true,
        };
        if role == OrgRole::Owner {
            return Ok(observed);
        }
        let mut unseen = false;
        for repo in &target.repos {
            let access = match repository_path(&repo.remote) {
                Some((owner, name)) => {
                    match app.repo_role(&session.token, &owner, &name, github_id, &login) {
                        Answer::Known(role) => {
                            RepoAccess::Known(github_members::repo_permissions(role))
                        }
                        // The token cannot see the repository. That is believed only while the
                        // organization is still the one the tenant was bound to (checked once
                        // after the loop): a renamed or transferred organization answers 404 for
                        // every path under its old name.
                        Answer::Absent => {
                            unseen = true;
                            RepoAccess::Known(sentinel_core::auth::Permissions::NONE)
                        }
                        // A rate limit says GitHub wants us to stop: keep what the walk settled so
                        // far and retry the rest under back-off.
                        Answer::Unknown {
                            retry_after_s: Some(_),
                        } => {
                            observed.complete = false;
                            break;
                        }
                        // Any other unknown answer is about this repository alone. Its grant is left
                        // as it is (it lapses with the grace period if GitHub never answers) and the
                        // walk goes on, so one repository that cannot be read does not hold back the
                        // rest.
                        Answer::Unknown {
                            retry_after_s: None,
                        } => RepoAccess::Unknown,
                    }
                }
                None => RepoAccess::Known(sentinel_core::auth::Permissions::NONE),
            };
            observed.repos.push((repo.repo, access));
        }
        if unseen {
            self.confirm_org(app, target, now)?;
        }
        Ok(observed)
    }

    fn confirm_absent(
        &mut self,
        app: &App,
        target: &Target,
        github_id: u64,
        now: UnixMillis,
    ) -> Result<Observed, Option<i64>> {
        self.confirm_org(app, target, now)?;
        Ok(Observed {
            github_id: Some(github_id),
            membership: Membership::Absent,
            repos: Vec::new(),
            complete: true,
        })
    }

    /// Fetches the installation snapshot again and proves it still names the organization the tenant was
    /// bound to; otherwise the cached session is dropped and the answer is unreachable, never a removal.
    fn confirm_org(
        &mut self,
        app: &App,
        target: &Target,
        now: UnixMillis,
    ) -> Result<(), Option<i64>> {
        let fresh = match app.installation_status(target.installation, now.0) {
            Ok(Some(installed)) => installed,
            _ => {
                self.sessions.remove(&target.installation);
                return Err(None);
            }
        };
        let same = !fresh.personal
            && fresh.account_id == target.org_id
            && self
                .sessions
                .get(&target.installation)
                .is_some_and(|s| s.org_login == fresh.login);
        if !same {
            self.sessions.remove(&target.installation);
            return Err(None);
        }
        Ok(())
    }

    fn session(
        &mut self,
        app: &App,
        target: &Target,
        now: UnixMillis,
    ) -> Result<&Session, Option<i64>> {
        let fresh_enough = self
            .sessions
            .get(&target.installation)
            .is_some_and(|s| s.token.expires_ms > now.0 + TOKEN_MARGIN_MS);
        if !fresh_enough {
            let installed = match app.installation_status(target.installation, now.0) {
                Ok(Some(installed)) => installed,
                _ => return Err(None),
            };
            if installed.personal || installed.account_id != target.org_id {
                self.sessions.remove(&target.installation);
                return Err(None);
            }
            let token = match app.membership_token(&installed, now.0) {
                Ok(token) => token,
                Err(_) => return Err(None),
            };
            self.sessions.retain(|_, s| s.token.expires_ms > now.0);
            if self.sessions.len() >= MAX_CACHED
                && !self.sessions.contains_key(&target.installation)
                && let Some(oldest) = self
                    .sessions
                    .iter()
                    .min_by_key(|(_, s)| s.token.expires_ms)
                    .map(|(key, _)| *key)
            {
                self.sessions.remove(&oldest);
            }
            self.sessions.insert(
                target.installation,
                Session {
                    token,
                    org_login: installed.login,
                    org_id: installed.account_id,
                },
            );
        }
        self.sessions.get(&target.installation).ok_or(None)
    }
}

/// Sleeps until a commit may have queued work or the earliest row falls due, never longer than `config.idle`.
fn sleep_until_work(
    store: &Store,
    config: &Config,
    settled: &(std::sync::Mutex<bool>, std::sync::Condvar),
    seen: u64,
    polled: Instant,
) {
    let ceiling = polled + config.idle;
    // A commit since `seen` ends the wait at once, so the earliest-row read would be wasted: on a busy
    // store this keeps the lane at one read per gap, as the fixed poll it replaced.
    let deadline = if store.changes().generation() != seen {
        ceiling
    } else {
        match store.read(github_members::next_due_ms) {
            Ok(Some(due_ms)) => {
                let wait_ms = due_ms.saturating_sub(UnixMillis::now().0).max(0) as u64;
                (polled + Duration::from_millis(wait_ms)).min(ceiling)
            }
            _ => ceiling,
        }
    };
    store.changes().wait_past(seen, deadline);
    if let Some(rest) = COMMIT_GAP.min(config.idle).checked_sub(polled.elapsed()) {
        wait(settled, rest);
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
