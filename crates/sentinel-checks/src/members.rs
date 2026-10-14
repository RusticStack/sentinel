//! The GitHub-backed membership lane.
//!
//! `github_member_checks` rows are the durable list of (tenant, person) pairs
//! owed a check: a sign-in, a link, a signed webhook or the periodic pass
//! asked for one. The lane *observes* GitHub — the person's current login
//! from their immutable numeric id, their membership of the organization, and
//! their permission on each bound repository, all through the installation's
//! token — and hands the observation to
//! [`sentinel_store::github_members::apply`], which decides inside one writer
//! transaction. The lane never decides and never holds the writer while a
//! request is on the wire.
//!
//! Only verified answers change anything. A 404 for a membership is "not a
//! member" only after the organization's own identity was confirmed again; a
//! rate limit, a server error, a missing App permission, an unreachable
//! network or a reply about a different account or organization is *unknown*:
//! what exists is kept until the grace period since GitHub last confirmed it
//! is over, nothing new is granted, and the pair is retried under back-off.
//! A rate limit also pauses that installation for the time GitHub asked.

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
    app::{Answer, App, OrgRole, Token},
    checks::repository_path,
};
use sentinel_store::{
    Store,
    github_members::{self, Check, Membership, Observed, RepoAccess, Target, Timing},
};

/// How long before expiry a cached token is replaced.
const TOKEN_MARGIN_MS: i64 = 120_000;
/// One cached token per installation; bounded like the other lanes' caches.
const MAX_CACHED: usize = 1024;
/// The longest the lane honours a "retry later" from GitHub for one
/// installation, whatever it asked for.
const MAX_PAUSE_MS: i64 = 60 * 60 * 1000;

/// Pacing and policy of the lane.
#[derive(Clone, Copy, Debug)]
pub struct Config {
    pub idle: Duration,
    pub min_backoff: Duration,
    pub max_backoff: Duration,
    /// How often a settled member is confirmed, and how long an unconfirmed
    /// one keeps access ([`Timing`]).
    pub timing: Timing,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            idle: Duration::from_millis(250),
            min_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(30),
            timing: Timing {
                recheck_ms: DEFAULT_RECHECK_MS,
                grace_ms: DEFAULT_GRACE_MS,
            },
        }
    }
}

/// An hour between confirmations of a settled member: with signed webhooks
/// the common change is seen at once, and the request budget is
/// roughly `members x (2 + repositories) / recheck` per hour.
pub const DEFAULT_RECHECK_MS: i64 = 60 * 60 * 1000;
/// A day of access without confirmation before it is removed.
pub const DEFAULT_GRACE_MS: i64 = 24 * 60 * 60 * 1000;

/// One pass's outcome, for the caller's diagnostics. Carries no login, id or
/// token.
#[derive(Clone, Debug)]
pub struct Notice {
    pub outcome: String,
}

/// A running lane; dropping it stops and joins the thread.
pub struct Members {
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
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// What the lane keeps per installation: a members-read token and the
/// organization's identity as the installation snapshot reported it when the
/// token was minted.
struct Session {
    token: Token,
    org_login: String,
    org_id: u64,
}

struct Worker {
    store: Arc<Store>,
    app: Arc<App>,
    sessions: HashMap<u64, Session>,
    /// Installations GitHub asked the lane to leave alone, until this time.
    paused: HashMap<u64, i64>,
}

/// The outcome of a pass whose result the store would not take.
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
    while !stop.load(Ordering::Acquire) {
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
            wait(settled, config.idle);
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
    /// One pair: read what the pass needs, ask GitHub, commit the verdict.
    fn pass(&mut self, check: &Check, timing: Timing) -> String {
        let target = match self.store.read(|c| github_members::target(c, check)) {
            Ok(Some(target)) => target,
            Ok(None) => {
                let check = *check;
                return match self
                    .store
                    .writer()
                    .write(move |tx| github_members::finish(tx, &check))
                {
                    Ok(()) => "target gone".into(),
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

    /// Commit "GitHub could not be asked": what exists is kept within grace,
    /// the pair backs off, and a rate-limit hint is honoured within a bound.
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

    /// Ask GitHub about one pair. `Err` carries the pause GitHub asked for
    /// (if any) when nothing could be established.
    fn observe(&mut self, target: &Target, now: UnixMillis) -> Result<Observed, Option<i64>> {
        let Some(github_id) = target.github_id else {
            // No linked account: nothing to ask, and nothing can confirm.
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
            // GitHub said "later": leave the whole installation alone.
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
            // The account was deleted: no organization keeps a member that
            // does not exist, and the numeric id will never be reused.
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
                // "Not a member" is only believed about the organization the
                // tenant was bound to: confirm its identity again before
                // anyone loses access over a 404 (a renamed organization
                // answers 404 under its old name).
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
            // An organization owner reaches every repository already.
            return Ok(observed);
        }
        for repo in &target.repos {
            let access = match repository_path(&repo.remote) {
                Some((owner, name)) => {
                    match app.repo_role(&session.token, &owner, &name, github_id, &login) {
                        Answer::Known(role) => {
                            RepoAccess::Known(github_members::repo_permissions(role))
                        }
                        // An unparseable approved remote cannot be verified:
                        // no access, never a guess.
                        Answer::Absent => RepoAccess::Known(sentinel_core::auth::Permissions::NONE),
                        Answer::Unknown { .. } => RepoAccess::Unknown,
                    }
                }
                None => RepoAccess::Known(sentinel_core::auth::Permissions::NONE),
            };
            if access == RepoAccess::Unknown {
                // Stop at the first unknown: the settled prefix is applied,
                // the walk resumes from there after a back-off.
                observed.complete = false;
                break;
            }
            observed.repos.push((repo.repo, access));
        }
        Ok(observed)
    }

    /// A 404 for the membership: believe it only when the installation still
    /// reports the same organization (id and login) that was asked about.
    fn confirm_absent(
        &mut self,
        app: &App,
        target: &Target,
        github_id: u64,
        now: UnixMillis,
    ) -> Result<Observed, Option<i64>> {
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
        Ok(Observed {
            github_id: Some(github_id),
            membership: Membership::Absent,
            repos: Vec::new(),
            complete: true,
        })
    }

    /// The installation's members-read token and organization identity,
    /// cached until close to expiry. The snapshot is fetched on a miss: the
    /// same read that decides whether minting is allowed at all.
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
            // The organization the tenant was bound to, and no other: a
            // transferred installation never reauthorizes its old members.
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
