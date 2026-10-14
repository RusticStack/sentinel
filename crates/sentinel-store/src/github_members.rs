//! GitHub-backed organization membership.
//!
//! A tenant is *app-managed* (invitation or administrator) or *GitHub-backed*
//! (`tenants.membership_source = 1`). In a GitHub-backed tenant a person is a
//! member only while GitHub says the **linked, verified GitHub account** (the
//! immutable numeric id in `external_identities`, never a login name) belongs
//! to the organization the tenant's installation is bound to. Rows derived
//! from GitHub carry `synced_ms`, the time GitHub last confirmed them; a row
//! whose confirmation is older than the grace period is removed by the lane.
//!
//! This module holds every decision that touches the database; the network
//! half is the lane in `sentinel-checks`, which only *observes* GitHub and
//! hands the observation to [`apply`]. A webhook is a hint ([`hint`]) except
//! for a signed `member_removed`, which revokes at once and also asks for a
//! check so a stale or replayed removal heals itself ([`member_removed`]).
//!
//! Authorization queries never read `synced_ms`: derived rows are ordinary
//! memberships and repository grants, so nothing on the request path changed
//! and a removal is effective on the next query. Long-lived readers see the
//! tenant's authorization epoch move in the same transaction.
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sentinel_core::{
    RepoId, TenantId, UnixMillis, UserId,
    auth::{Permissions, Role},
};

use crate::{
    Error, Result,
    auth::Authority,
    local_auth::{Event, audit},
};

/// The provider key of the linked identity a derived membership rests on.
pub const PROVIDER: &str = "github";

/// Repositories whose permission one step of the walk asks GitHub about. A
/// member of a large installation is checked in several bounded steps.
pub const REPOS_PER_STEP: u32 = 25;

/// An on-demand request ([`enqueue_user`]) for a pair checked more recently
/// than this does nothing: sign-in spam cannot become a stream of GitHub
/// requests. A signed webhook is exempt.
pub const MIN_ON_DEMAND_GAP_MS: i64 = 60_000;

/// Most tenants one sign-in schedules a check for.
const MAX_TENANTS_PER_SIGN_IN: i64 = 256;

/// A candidate with no membership is dropped after this many failed checks;
/// the next sign-in or signed event asks again.
const MAX_CANDIDATE_ATTEMPTS: u32 = 5;

/// GitHub's two organization roles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OrgRole {
    Owner,
    Member,
}

impl OrgRole {
    /// The Sentinel role GitHub's answer maps to: an organization owner
    /// administers the tenant; any other member is an operator, the ceiling
    /// under which the repository permissions derived from GitHub apply (a
    /// reader ceiling would make GitHub's `write` meaningless).
    pub const fn role(self) -> Role {
        match self {
            OrgRole::Owner => Role::TenantAdmin,
            OrgRole::Member => Role::Operator,
        }
    }
}

/// What GitHub said about a person's membership. `Unknown` is an answer that
/// proves nothing (rate limit, server error, missing App permission, an
/// identity mismatch): it keeps what exists for the grace period and grants
/// nothing new.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Membership {
    Active(OrgRole),
    Absent,
    Unknown,
}

/// What GitHub said about a person's permission on one repository.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RepoAccess {
    /// The bits derived from the answer; [`Permissions::NONE`] is a verified
    /// "no access".
    Known(Permissions),
    Unknown,
}

/// The Sentinel repository permission bits for a GitHub repository role, never
/// above what the person holds there:
///
/// | GitHub role | Sentinel bits |
/// |---|---|
/// | `admin` | read, run, write secrets |
/// | `maintain`, `write` | read, run |
/// | `triage`, `read` | read |
/// | `none`, anything else | none |
///
/// An unrecognized role (a custom role GitHub added later) maps to none: a
/// guess is never an authorization.
pub const fn repo_permissions(role: &str) -> Permissions {
    // `const fn` cannot compare `&str` with `==`; compare the bytes.
    const fn is(role: &str, expected: &str) -> bool {
        let (a, b) = (role.as_bytes(), expected.as_bytes());
        if a.len() != b.len() {
            return false;
        }
        let mut i = 0;
        while i < a.len() {
            if a[i] != b[i] {
                return false;
            }
            i += 1;
        }
        true
    }
    if is(role, "admin") {
        Permissions::READ
            .union(Permissions::RUN)
            .union(Permissions::WRITE_SECRETS)
    } else if is(role, "maintain") || is(role, "write") {
        Permissions::READ.union(Permissions::RUN)
    } else if is(role, "triage") || is(role, "read") {
        Permissions::READ
    } else {
        Permissions::NONE
    }
}

/// Whether the tenant's membership comes from GitHub.
pub fn is_github_backed(conn: &Connection, tenant: TenantId) -> Result<bool> {
    Ok(conn
        .prepare_cached("SELECT membership_source = 1 FROM tenants WHERE id = ?1")?
        .query_row([tenant.as_bytes()], |r| r.get::<_, bool>(0))
        .optional()?
        .unwrap_or(false))
}

/// Refuse a manual membership change in a GitHub-backed tenant. `human` names
/// the person the change is about: service accounts are always managed here
/// (they have no GitHub identity); `None` means a change to the tenant as a
/// whole (an invitation to it). The refusal is `Forbidden`: policy, not a
/// race.
pub(crate) fn require_app_managed(
    conn: &Connection,
    tenant: TenantId,
    human: Option<UserId>,
) -> Result<()> {
    let backed: bool = conn
        .prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM tenants t WHERE t.id = ?1 AND t.membership_source = 1
             AND (?2 IS NULL OR EXISTS(SELECT 1 FROM users u WHERE u.id = ?2 AND u.kind = 0)))",
        )?
        .query_row(
            params![tenant.as_bytes(), human.as_ref().map(UserId::as_bytes)],
            |r| r.get(0),
        )?;
    if backed {
        Err(Error::Forbidden)
    } else {
        Ok(())
    }
}

/// Make a tenant GitHub-backed (or app-managed again). Needs administration
/// of the tenant with fresh step-up ([`Authority::require_tenant_access_change`],
/// strict), and — because the change removes every member GitHub does not
/// confirm — a converting administrator who is a member must already have a
/// linked GitHub account, so the change cannot lock the person making it out.
pub fn set_backing(
    tx: &Transaction<'_>,
    authority: Authority,
    tenant: TenantId,
    github: bool,
    reason: Option<&str>,
    now: UnixMillis,
) -> Result<()> {
    let principal = authority.require_tenant_access_change(tx, tenant, true, reason)?;
    if github {
        let locks_out_actor: bool = tx
            .prepare_cached(
                "SELECT EXISTS(SELECT 1 FROM memberships WHERE tenant_id = ?1 AND user_id = ?2)
                 AND NOT EXISTS(SELECT 1 FROM external_identities
                                WHERE provider = ?3 AND user_id = ?2)",
            )?
            .query_row(
                params![tenant.as_bytes(), principal.user.as_bytes(), PROVIDER],
                |r| r.get(0),
            )?;
        if locks_out_actor {
            return Err(Error::InvalidInput("link a github account first"));
        }
    }
    apply_backing(tx, tenant, github, Some(principal.user), false, now)
}

/// [`set_backing`] for the host-local operator, who holds the database file's
/// authority and has no principal to attribute.
pub fn set_backing_trusted(
    tx: &Transaction<'_>,
    tenant: TenantId,
    github: bool,
    now: UnixMillis,
) -> Result<()> {
    apply_backing(tx, tenant, github, None, true, now)
}

fn apply_backing(
    tx: &Transaction<'_>,
    tenant: TenantId,
    github: bool,
    actor: Option<UserId>,
    host_local: bool,
    now: UnixMillis,
) -> Result<()> {
    let (kind, source): (i64, i64) = tx
        .prepare_cached("SELECT kind, membership_source FROM tenants WHERE id = ?1")?
        .query_row([tenant.as_bytes()], |r| Ok((r.get(0)?, r.get(1)?)))
        .optional()?
        .ok_or(Error::NotFound)?;
    if github {
        if kind != 0 {
            return Err(Error::InvalidInput("organization"));
        }
        // Verified, not assumed: the installation snapshot must have proved
        // the account an organization.
        let organization: bool = tx
            .prepare_cached(
                "SELECT EXISTS(SELECT 1 FROM installations WHERE tenant_id = ?1 AND provider = ?2
                 AND account_personal = 0 AND account_id IS NOT NULL)",
            )?
            .query_row(params![tenant.as_bytes(), PROVIDER], |r| r.get(0))?;
        if !organization {
            return Err(Error::Conflict);
        }
        if source == 1 {
            return Ok(());
        }
        tx.execute(
            "UPDATE tenants SET membership_source = 1 WHERE id = ?1",
            [tenant.as_bytes()],
        )?;
        // Existing human members start their grace clock now: they are
        // verified against GitHub in the next passes and removed if nothing
        // confirms them. Service accounts stay app-managed.
        tx.execute(
            "UPDATE memberships SET synced_ms = ?2 WHERE tenant_id = ?1 AND synced_ms IS NULL
             AND user_id IN (SELECT id FROM users WHERE kind = 0)",
            params![tenant.as_bytes(), now.0],
        )?;
        tx.execute(
            "UPDATE repo_grants SET synced_ms = ?2 WHERE tenant_id = ?1 AND synced_ms IS NULL
             AND user_id IN (SELECT id FROM users WHERE kind = 0)",
            params![tenant.as_bytes(), now.0],
        )?;
        tx.execute(
            "INSERT INTO github_member_checks(tenant_id, user_id, next_ms)
             SELECT tenant_id, user_id, ?2 FROM memberships
             WHERE tenant_id = ?1 AND synced_ms IS NOT NULL
             ON CONFLICT(tenant_id, user_id) DO UPDATE SET
                next_ms = MIN(next_ms, excluded.next_ms), seq = seq + 1",
            params![tenant.as_bytes(), now.0],
        )?;
    } else {
        if source == 0 {
            return Ok(());
        }
        tx.execute(
            "UPDATE tenants SET membership_source = 0 WHERE id = ?1",
            [tenant.as_bytes()],
        )?;
        // What GitHub granted stays as ordinary, now locally managed access:
        // an administrator decides what happens to it from here.
        tx.execute(
            "UPDATE memberships SET synced_ms = NULL WHERE tenant_id = ?1 AND synced_ms IS NOT NULL",
            [tenant.as_bytes()],
        )?;
        tx.execute(
            "UPDATE repo_grants SET synced_ms = NULL WHERE tenant_id = ?1 AND synced_ms IS NOT NULL",
            [tenant.as_bytes()],
        )?;
        tx.execute(
            "DELETE FROM github_member_checks WHERE tenant_id = ?1",
            [tenant.as_bytes()],
        )?;
    }
    crate::tenancy::bump_epoch(tx, tenant)?;
    audit(
        tx,
        Event::TenantBackingChanged,
        actor,
        None,
        host_local,
        Some(if github { "github" } else { "app" }),
    )
}

/// Return a tenant to app-managed membership when its last organization
/// installation is released (called from the unbind path, in its
/// transaction).
pub(crate) fn installation_released(
    tx: &Transaction<'_>,
    tenant: TenantId,
    now: UnixMillis,
) -> Result<()> {
    let still_backed: bool = tx
        .prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM installations WHERE tenant_id = ?1 AND provider = ?2
             AND account_personal = 0)",
        )?
        .query_row(params![tenant.as_bytes(), PROVIDER], |r| r.get(0))?;
    if still_backed {
        return Ok(());
    }
    apply_backing(tx, tenant, false, None, false, now)
}

/// Ask for a check of one person in every GitHub-backed tenant, as a sign-in
/// or a new link does. Nothing is queued for a person with no linked GitHub
/// account, and a pair checked within [`MIN_ON_DEMAND_GAP_MS`] is left alone.
/// Bounded; the request path never waits for GitHub.
pub fn enqueue_user(tx: &Transaction<'_>, user: UserId, now: UnixMillis) -> Result<usize> {
    Ok(tx
        .prepare_cached(
            "INSERT INTO github_member_checks(tenant_id, user_id, next_ms)
             SELECT t.id, ?1, ?2 FROM tenants t
             WHERE t.membership_source = 1 AND t.active = 1
               AND EXISTS(SELECT 1 FROM external_identities e
                          WHERE e.provider = ?3 AND e.user_id = ?1)
             LIMIT ?5
             ON CONFLICT(tenant_id, user_id) DO UPDATE SET
                next_ms = MIN(next_ms, excluded.next_ms), seq = seq + 1
             WHERE checked_ms <= ?2 - ?4",
        )?
        .execute(params![
            user.as_bytes(),
            now.0,
            PROVIDER,
            MIN_ON_DEMAND_GAP_MS,
            MAX_TENANTS_PER_SIGN_IN
        ])?)
}

/// The rate-limited request a member opening a GitHub-backed tenant makes:
/// schedule one check when the membership's last confirmation is older than
/// `ttl_ms`. A read tells whether anything is owed, so the common case writes
/// nothing.
pub fn touch(
    conn: &Connection,
    tenant: TenantId,
    user: UserId,
    ttl_ms: i64,
    now: UnixMillis,
) -> Result<bool> {
    let stale: bool = conn
        .prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM memberships m JOIN tenants t ON t.id = m.tenant_id
             WHERE m.tenant_id = ?1 AND m.user_id = ?2 AND t.membership_source = 1
               AND m.synced_ms IS NOT NULL AND m.synced_ms <= ?3)",
        )?
        .query_row(
            params![
                tenant.as_bytes(),
                user.as_bytes(),
                now.0.saturating_sub(ttl_ms)
            ],
            |r| r.get(0),
        )?;
    Ok(stale)
}

/// Queue one pair for an immediate check (signed webhook, administrator).
/// A tenant that is not GitHub-backed queues nothing.
fn enqueue_pair(
    tx: &Transaction<'_>,
    tenant: TenantId,
    user: UserId,
    now: UnixMillis,
) -> Result<()> {
    tx.execute(
        "INSERT INTO github_member_checks(tenant_id, user_id, next_ms)
         SELECT ?1, ?2, ?3 WHERE EXISTS(SELECT 1 FROM tenants WHERE id = ?1 AND membership_source = 1)
         ON CONFLICT(tenant_id, user_id) DO UPDATE SET
            next_ms = MIN(next_ms, excluded.next_ms), seq = seq + 1",
        params![tenant.as_bytes(), user.as_bytes(), now.0],
    )?;
    Ok(())
}

/// The Sentinel account a GitHub numeric id is linked to, if any.
fn linked_user(conn: &Connection, github_id: u64) -> Result<Option<UserId>> {
    conn.prepare_cached(
        "SELECT user_id FROM external_identities WHERE provider = ?1 AND subject = ?2",
    )?
    .query_row(params![PROVIDER, github_id.to_string()], |r| {
        r.get::<_, [u8; 16]>(0)
    })
    .optional()?
    .map(|bytes| UserId::from_bytes(bytes).map_err(|_| Error::Corrupt("user_id")))
    .transpose()
}

/// A signed event says something changed about one person (`Some`) or about
/// the whole organization (`None`: a team or repository access change).
/// Positive information is a hint only: it schedules a check, never grants.
pub fn hint(
    tx: &Transaction<'_>,
    tenant: TenantId,
    github_user: Option<u64>,
    now: UnixMillis,
) -> Result<()> {
    match github_user {
        Some(id) => {
            if let Some(user) = linked_user(tx, id)? {
                enqueue_pair(tx, tenant, user, now)?;
            }
        }
        None => {
            tx.execute(
                "UPDATE github_member_checks SET next_ms = MIN(next_ms, ?2), seq = seq + 1,
                    cursor = NULL WHERE tenant_id = ?1",
                params![tenant.as_bytes(), now.0],
            )?;
        }
    }
    Ok(())
}

/// A signed `member_removed`: revoke the derived access of the linked account
/// immediately, then ask for a check. If the removal was stale or replayed,
/// the check restores whatever GitHub still confirms; if it was current, the
/// check finds nothing to restore. Returns whether access was removed.
pub fn member_removed(
    tx: &Transaction<'_>,
    tenant: TenantId,
    github_user: u64,
    now: UnixMillis,
) -> Result<bool> {
    let Some(user) = linked_user(tx, github_user)? else {
        return Ok(false);
    };
    if !is_github_backed(tx, tenant)? {
        return Ok(false);
    }
    let removed = remove_derived(tx, tenant, user, now, "webhook")?;
    enqueue_pair(tx, tenant, user, now)?;
    Ok(removed)
}

/// Delete one person's membership of a GitHub-backed tenant and everything
/// that hung on it: repository grants cascade, credentials narrowed to the
/// tenant and OAuth grants for it are revoked, and the tenant's authorization
/// epoch moves, all in the caller's transaction. The caller has established
/// that the tenant is GitHub-backed. Skips the keep-an-administrator rule on
/// purpose: GitHub, not Sentinel, decides who administers the organization.
fn remove_derived(
    tx: &Transaction<'_>,
    tenant: TenantId,
    user: UserId,
    now: UnixMillis,
    why: &str,
) -> Result<bool> {
    let removed = tx.execute(
        "DELETE FROM memberships WHERE tenant_id = ?1 AND user_id = ?2
         AND user_id IN (SELECT id FROM users WHERE kind = 0)",
        params![tenant.as_bytes(), user.as_bytes()],
    )?;
    if removed == 0 {
        return Ok(false);
    }
    tx.execute(
        "UPDATE api_tokens SET revoked_ms = ?3 WHERE user_id = ?1 AND tenant_id = ?2
         AND revoked_ms IS NULL",
        params![user.as_bytes(), tenant.as_bytes(), now.0],
    )?;
    crate::oauth::revoke_for_membership(tx, user, tenant, now)?;
    crate::tenancy::bump_epoch(tx, tenant)?;
    audit(
        tx,
        Event::GithubMemberRemoved,
        None,
        Some(user),
        false,
        Some(why),
    )?;
    Ok(true)
}

/// A person's GitHub link was removed: every derived membership of theirs
/// ends in the same transaction as the unlink, and nothing remains queued for
/// them. Leaving one organization is not this: that is [`apply`] with
/// [`Membership::Absent`], which touches only that tenant.
pub(crate) fn identity_unlinked(
    tx: &Transaction<'_>,
    user: UserId,
    now: UnixMillis,
) -> Result<usize> {
    let tenants: Vec<[u8; 16]> = tx
        .prepare_cached(
            "SELECT m.tenant_id FROM memberships m JOIN tenants t ON t.id = m.tenant_id
             WHERE m.user_id = ?1 AND m.synced_ms IS NOT NULL AND t.membership_source = 1",
        )?
        .query_map([user.as_bytes()], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    let mut removed = 0;
    for tenant in tenants {
        let tenant = TenantId::from_bytes(tenant).map_err(|_| Error::Corrupt("tenant_id"))?;
        if remove_derived(tx, tenant, user, now, "unlinked")? {
            removed += 1;
        }
    }
    tx.execute(
        "DELETE FROM github_member_checks WHERE user_id = ?1",
        [user.as_bytes()],
    )?;
    Ok(removed)
}

/// Enqueue every derived member of a GitHub-backed tenant that has no queue
/// row: at start, so a lost queue never means an unverified member.
pub fn seed(tx: &Transaction<'_>, now: UnixMillis) -> Result<()> {
    tx.execute(
        "INSERT OR IGNORE INTO github_member_checks(tenant_id, user_id, next_ms)
         SELECT m.tenant_id, m.user_id, ?1 FROM memberships m
         JOIN tenants t ON t.id = m.tenant_id
         WHERE t.membership_source = 1 AND m.synced_ms IS NOT NULL",
        [now.0],
    )?;
    Ok(())
}

/// One due pair, with the fence its outcome is written under.
#[derive(Clone, Copy, Debug)]
pub struct Check {
    pub tenant: TenantId,
    pub user: UserId,
    pub seq: i64,
    pub attempts: u32,
    /// The last repository whose permission an earlier step settled.
    pub cursor: Option<RepoId>,
}

pub fn due(conn: &Connection, now: UnixMillis) -> Result<Option<Check>> {
    type Row = ([u8; 16], [u8; 16], i64, i64, Option<[u8; 16]>);
    let row: Option<Row> = conn
        .prepare_cached(
            "SELECT tenant_id, user_id, seq, attempts, cursor FROM github_member_checks
             WHERE next_ms <= ?1 ORDER BY next_ms, tenant_id, user_id LIMIT 1",
        )?
        .query_row([now.0], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
        })
        .optional()?;
    row.map(|(tenant, user, seq, attempts, cursor)| {
        Ok(Check {
            tenant: TenantId::from_bytes(tenant).map_err(|_| Error::Corrupt("tenant_id"))?,
            user: UserId::from_bytes(user).map_err(|_| Error::Corrupt("user_id"))?,
            seq,
            attempts: u32::try_from(attempts).unwrap_or(u32::MAX),
            cursor: cursor
                .map(|c| RepoId::from_bytes(c).map_err(|_| Error::Corrupt("cursor")))
                .transpose()?,
        })
    })
    .transpose()
}

/// A repository the walk asks about: bound to the tenant's installation and
/// live, with the approved remote the owner/name comes from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetRepo {
    pub repo: RepoId,
    pub remote: String,
}

/// What a pass needs before it talks to GitHub.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    /// The installation's GitHub id, for minting a token.
    pub installation: u64,
    /// The organization's immutable GitHub account id.
    pub org_id: u64,
    /// The organization's current login, for URL paths only.
    pub org_login: String,
    /// Suspended or permission-invalid: GitHub cannot be asked.
    pub unusable: bool,
    /// The numeric id of the person's linked GitHub account.
    pub github_id: Option<u64>,
    /// The person's current Sentinel role in the tenant, when a member.
    pub member: Option<Role>,
    pub repos: Vec<TargetRepo>,
    /// More repositories follow `repos`.
    pub more: bool,
}

/// Read what a pass needs. `None` means the tenant is no longer GitHub-backed
/// by a verified organization installation: the caller drops the row.
pub fn target(conn: &Connection, check: &Check) -> Result<Option<Target>> {
    type Install = (String, i64, String, bool);
    let install: Option<Install> = conn
        .prepare_cached(
            "SELECT i.external_id, i.account_id, i.account_login,
                    (i.suspended = 1 OR i.permissions_valid = 0)
             FROM installations i JOIN tenants t ON t.id = i.tenant_id
             WHERE i.tenant_id = ?1 AND i.provider = ?2 AND i.account_personal = 0
               AND i.account_id IS NOT NULL AND t.membership_source = 1 AND t.active = 1
             ORDER BY i.bound_ms, i.id LIMIT 1",
        )?
        .query_row(params![check.tenant.as_bytes(), PROVIDER], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
        })
        .optional()?;
    let Some((external, account, login, unusable)) = install else {
        return Ok(None);
    };
    let github_id: Option<String> = conn
        .prepare_cached(
            "SELECT subject FROM external_identities WHERE provider = ?1 AND user_id = ?2",
        )?
        .query_row(params![PROVIDER, check.user.as_bytes()], |r| r.get(0))
        .optional()?;
    let role: Option<i64> = conn
        .prepare_cached("SELECT role FROM memberships WHERE tenant_id = ?1 AND user_id = ?2")?
        .query_row(
            params![check.tenant.as_bytes(), check.user.as_bytes()],
            |r| r.get(0),
        )
        .optional()?;
    let mut repos = Vec::new();
    let mut more = false;
    let mut stmt = conn.prepare_cached(
        "SELECT b.repo_id, b.binding FROM source_bindings b
         JOIN installations i ON i.id = b.installation_id AND i.tenant_id = b.tenant_id
         WHERE b.tenant_id = ?1 AND b.revoked = 0 AND i.provider = ?2 AND i.account_personal = 0
           AND b.repo_id > ?3 ORDER BY b.repo_id LIMIT ?4",
    )?;
    let rows = stmt.query_map(
        params![
            check.tenant.as_bytes(),
            PROVIDER,
            check.cursor.as_ref().map_or(&[0u8; 16], RepoId::as_bytes),
            REPOS_PER_STEP + 1
        ],
        |r| Ok((r.get::<_, [u8; 16]>(0)?, r.get::<_, Vec<u8>>(1)?)),
    )?;
    for row in rows {
        let (repo, binding) = row?;
        if repos.len() as u32 == REPOS_PER_STEP {
            more = true;
            break;
        }
        let binding: sentinel_protocol::source::Binding =
            serde_json::from_slice(&binding).map_err(|_| Error::Corrupt("source binding"))?;
        repos.push(TargetRepo {
            repo: RepoId::from_bytes(repo).map_err(|_| Error::Corrupt("repo_id"))?,
            remote: binding.remote,
        });
    }
    Ok(Some(Target {
        installation: external
            .parse()
            .map_err(|_| Error::Corrupt("installation id"))?,
        org_id: u64::try_from(account).map_err(|_| Error::Corrupt("account"))?,
        org_login: login,
        unusable,
        github_id: github_id
            .map(|s| s.parse().map_err(|_| Error::Corrupt("github subject")))
            .transpose()?,
        member: match role {
            Some(1) => Some(Role::Reader),
            Some(2) => Some(Role::Operator),
            Some(3) => Some(Role::TenantAdmin),
            Some(_) => return Err(Error::Corrupt("memberships.role")),
            None => None,
        },
        repos,
        more,
    }))
}

/// How the lane paces what it writes.
#[derive(Clone, Copy, Debug)]
pub struct Timing {
    /// The interval between confirmations of a settled member.
    pub recheck_ms: i64,
    /// How long an unconfirmed member keeps access.
    pub grace_ms: i64,
}

/// What a pass observed. `repos` holds only repositories whose answer was
/// settled, in repository-id order; `complete` is false when the walk stopped
/// at an unknown answer.
#[derive(Clone, Debug)]
pub struct Observed {
    pub github_id: Option<u64>,
    pub membership: Membership,
    pub repos: Vec<(RepoId, RepoAccess)>,
    pub complete: bool,
}

/// Commit one pass. Every decision is made here, inside the writer
/// transaction, from the observation and the rows as they are now:
///
/// - the identity is read again and must still be the one observed, so a
///   relink or unlink while the request was on the wire discards the answer;
/// - `Active` creates or updates the membership, maps owner to administrator
///   and member to operator (a demotion follows GitHub), and derives the
///   person's repository grants from what GitHub reported, never above it;
/// - `Absent` (and a missing link past its grace) removes the membership with
///   everything that hung on it;
/// - `Unknown` keeps what exists until the grace period since the last
///   confirmation is over, grants nothing, and retries under back-off.
///
/// Returns a bounded outcome label for diagnostics: no ids, logins or tokens.
pub fn apply(
    tx: &Transaction<'_>,
    check: &Check,
    more_repos: bool,
    observed: &Observed,
    timing: Timing,
    now: UnixMillis,
) -> Result<&'static str> {
    if !is_github_backed(tx, check.tenant)? {
        drop_row(tx, check)?;
        return Ok("not github-backed");
    }
    let linked: Option<String> = tx
        .prepare_cached(
            "SELECT subject FROM external_identities WHERE provider = ?1 AND user_id = ?2",
        )?
        .query_row(params![PROVIDER, check.user.as_bytes()], |r| r.get(0))
        .optional()?;
    let linked = linked.and_then(|s| s.parse::<u64>().ok());
    if linked != observed.github_id {
        // The link changed while the request was out: that answer is about
        // somebody else. Ask again at once; nothing is applied.
        reschedule(tx, check, now.0, check.attempts, check.cursor)?;
        return Ok("identity changed");
    }
    let existing: Option<(i64, Option<i64>)> = tx
        .prepare_cached(
            "SELECT m.role, m.synced_ms FROM memberships m JOIN users u ON u.id = m.user_id
             WHERE m.tenant_id = ?1 AND m.user_id = ?2 AND u.kind = 0",
        )?
        .query_row(
            params![check.tenant.as_bytes(), check.user.as_bytes()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    // A human membership the tenant held before it was converted, or one a
    // trusted tool wrote since: its grace clock starts when it is first seen.
    if let Some((_, None)) = existing {
        tx.execute(
            "UPDATE memberships SET synced_ms = ?3 WHERE tenant_id = ?1 AND user_id = ?2",
            params![check.tenant.as_bytes(), check.user.as_bytes(), now.0],
        )?;
    }
    let last_confirmed = existing.and_then(|(_, synced)| synced).unwrap_or(now.0);
    let expired = now.0.saturating_sub(last_confirmed) >= timing.grace_ms;

    if observed.github_id.is_none() {
        // No linked GitHub account: nothing can confirm this person.
        return match existing {
            None => {
                drop_row(tx, check)?;
                Ok("nothing to check")
            }
            Some(_) if expired => {
                remove_derived(tx, check.tenant, check.user, now, "no linked account")?;
                drop_row(tx, check)?;
                Ok("removed: no linked account")
            }
            Some(_) => {
                reschedule(
                    tx,
                    check,
                    last_confirmed.saturating_add(timing.grace_ms),
                    0,
                    None,
                )?;
                Ok("waiting: no linked account")
            }
        };
    }

    match observed.membership {
        Membership::Absent => {
            let removed = remove_derived(tx, check.tenant, check.user, now, "not a member")?;
            drop_row(tx, check)?;
            Ok(if removed {
                "removed: not a member"
            } else {
                "not a member"
            })
        }
        Membership::Unknown => match existing {
            Some(_) if expired => {
                remove_derived(tx, check.tenant, check.user, now, "grace expired")?;
                drop_row(tx, check)?;
                Ok("removed: grace expired")
            }
            Some(_) => {
                retry(tx, check, now)?;
                Ok("kept: unknown")
            }
            None if check.attempts.saturating_add(1) >= MAX_CANDIDATE_ATTEMPTS => {
                drop_row(tx, check)?;
                Ok("dropped: unknown")
            }
            None => {
                retry(tx, check, now)?;
                Ok("retry: unknown")
            }
        },
        Membership::Active(org_role) => {
            let role = org_role.role();
            let mut changed = false;
            let outcome = match existing {
                None => {
                    let inserted = tx.execute(
                        "INSERT INTO memberships(tenant_id, user_id, role, synced_ms)
                         SELECT ?1, id, ?3, ?4 FROM users
                         WHERE id = ?2 AND active = 1 AND kind = 0",
                        params![
                            check.tenant.as_bytes(),
                            check.user.as_bytes(),
                            role as u8,
                            now.0
                        ],
                    )?;
                    if inserted == 0 {
                        drop_row(tx, check)?;
                        return Ok("account not active");
                    }
                    audit(
                        tx,
                        Event::GithubMemberJoined,
                        None,
                        Some(check.user),
                        false,
                        Some(role_label(role)),
                    )?;
                    changed = true;
                    "joined"
                }
                Some((old_role, _)) if old_role != i64::from(role as u8) => {
                    tx.execute(
                        "UPDATE memberships SET role = ?3, synced_ms = ?4
                         WHERE tenant_id = ?1 AND user_id = ?2",
                        params![
                            check.tenant.as_bytes(),
                            check.user.as_bytes(),
                            role as u8,
                            now.0
                        ],
                    )?;
                    audit(
                        tx,
                        Event::GithubMemberRoleChanged,
                        None,
                        Some(check.user),
                        false,
                        Some(role_label(role)),
                    )?;
                    changed = true;
                    "role changed"
                }
                Some(_) => {
                    tx.execute(
                        "UPDATE memberships SET synced_ms = ?3 WHERE tenant_id = ?1 AND user_id = ?2",
                        params![check.tenant.as_bytes(), check.user.as_bytes(), now.0],
                    )?;
                    "confirmed"
                }
            };
            changed |= settle_grants(tx, check, role, observed, timing, now)?;
            if changed {
                crate::tenancy::bump_epoch(tx, check.tenant)?;
            }
            // The walk continues while repositories remain or an answer was
            // unknown; a finished walk waits out the recheck interval.
            let cursor = observed
                .repos
                .last()
                .map(|(repo, _)| *repo)
                .or(check.cursor);
            if !observed.complete {
                retry_at(tx, check, now, cursor)?;
            } else if more_repos && role != Role::TenantAdmin {
                reschedule(tx, check, now.0.saturating_add(1_000), 0, cursor)?;
            } else {
                settle_row(tx, check, now, now.0.saturating_add(timing.recheck_ms))?;
            }
            Ok(outcome)
        }
    }
}

/// Derive the person's repository grants from the observation and sweep the
/// ones GitHub no longer stands behind. Returns whether any grant changed.
fn settle_grants(
    tx: &Transaction<'_>,
    check: &Check,
    role: Role,
    observed: &Observed,
    timing: Timing,
    now: UnixMillis,
) -> Result<bool> {
    let mut changed = 0;
    if role == Role::TenantAdmin {
        // An administrator reaches every repository of the tenant already; a
        // derived grant beside that would only outlive a demotion.
        changed += tx.execute(
            "DELETE FROM repo_grants WHERE tenant_id = ?1 AND user_id = ?2 AND synced_ms IS NOT NULL",
            params![check.tenant.as_bytes(), check.user.as_bytes()],
        )?;
        return Ok(changed > 0);
    }
    for (repo, access) in &observed.repos {
        let RepoAccess::Known(bits) = access else {
            continue;
        };
        if *bits == Permissions::NONE {
            changed += tx.execute(
                "DELETE FROM repo_grants WHERE tenant_id = ?1 AND user_id = ?2 AND repo_id = ?3",
                params![
                    check.tenant.as_bytes(),
                    check.user.as_bytes(),
                    repo.as_bytes()
                ],
            )?;
        } else {
            let current: Option<i64> = tx
                .prepare_cached(
                    "SELECT permissions FROM repo_grants
                     WHERE tenant_id = ?1 AND user_id = ?2 AND repo_id = ?3",
                )?
                .query_row(
                    params![
                        check.tenant.as_bytes(),
                        check.user.as_bytes(),
                        repo.as_bytes()
                    ],
                    |r| r.get(0),
                )
                .optional()?;
            if current == Some(i64::from(bits.bits())) {
                // Unchanged: only the confirmation time moves, and moving it
                // is not a change of anyone's access.
                tx.execute(
                    "UPDATE repo_grants SET synced_ms = ?4
                     WHERE tenant_id = ?1 AND user_id = ?2 AND repo_id = ?3",
                    params![
                        check.tenant.as_bytes(),
                        check.user.as_bytes(),
                        repo.as_bytes(),
                        now.0
                    ],
                )?;
                continue;
            }
            // Only a repository bound to the installation can be granted; the
            // composite foreign key also refuses another tenant's.
            changed += tx.execute(
                "INSERT INTO repo_grants(tenant_id, user_id, repo_id, permissions, synced_ms)
                 SELECT ?1, ?2, ?3, ?4, ?5 WHERE EXISTS(
                    SELECT 1 FROM source_bindings
                    WHERE repo_id = ?3 AND tenant_id = ?1 AND revoked = 0
                      AND installation_id IS NOT NULL)
                 ON CONFLICT(tenant_id, user_id, repo_id) DO UPDATE SET
                    permissions = excluded.permissions, synced_ms = excluded.synced_ms",
                params![
                    check.tenant.as_bytes(),
                    check.user.as_bytes(),
                    repo.as_bytes(),
                    bits.bits(),
                    now.0
                ],
            )?;
        }
    }
    // A repository no longer on the installation's list (its binding was
    // revoked), and a grant GitHub has not confirmed within the grace period.
    changed += tx.execute(
        "DELETE FROM repo_grants WHERE tenant_id = ?1 AND user_id = ?2 AND synced_ms IS NOT NULL
         AND (synced_ms <= ?3 OR repo_id NOT IN (
            SELECT repo_id FROM source_bindings
            WHERE tenant_id = ?1 AND revoked = 0 AND installation_id IS NOT NULL))",
        params![
            check.tenant.as_bytes(),
            check.user.as_bytes(),
            now.0.saturating_sub(timing.grace_ms)
        ],
    )?;
    Ok(changed > 0)
}

const fn role_label(role: Role) -> &'static str {
    match role {
        Role::Reader => "reader",
        Role::Operator => "operator",
        Role::TenantAdmin => "admin",
    }
}

/// Drop a pair whose target no longer exists (the tenant stopped being
/// GitHub-backed), fenced by the sequence the pass read.
pub fn finish(tx: &Transaction<'_>, check: &Check) -> Result<()> {
    drop_row(tx, check)
}

fn drop_row(tx: &Transaction<'_>, check: &Check) -> Result<()> {
    tx.execute(
        "DELETE FROM github_member_checks WHERE tenant_id = ?1 AND user_id = ?2 AND seq = ?3",
        params![check.tenant.as_bytes(), check.user.as_bytes(), check.seq],
    )?;
    Ok(())
}

/// Park the row at `next_ms` under the fence; a request that arrived while the
/// pass ran bumped `seq`, so this does nothing and the row stays due.
fn reschedule(
    tx: &Transaction<'_>,
    check: &Check,
    next_ms: i64,
    attempts: u32,
    cursor: Option<RepoId>,
) -> Result<()> {
    tx.execute(
        "UPDATE github_member_checks SET next_ms = ?4, attempts = ?5, cursor = ?6
         WHERE tenant_id = ?1 AND user_id = ?2 AND seq = ?3",
        params![
            check.tenant.as_bytes(),
            check.user.as_bytes(),
            check.seq,
            next_ms,
            attempts,
            cursor.as_ref().map(RepoId::as_bytes)
        ],
    )?;
    Ok(())
}

fn settle_row(tx: &Transaction<'_>, check: &Check, now: UnixMillis, next_ms: i64) -> Result<()> {
    tx.execute(
        "UPDATE github_member_checks SET next_ms = ?4, checked_ms = ?5, attempts = 0, cursor = NULL
         WHERE tenant_id = ?1 AND user_id = ?2 AND seq = ?3",
        params![
            check.tenant.as_bytes(),
            check.user.as_bytes(),
            check.seq,
            next_ms,
            now.0
        ],
    )?;
    Ok(())
}

fn retry(tx: &Transaction<'_>, check: &Check, now: UnixMillis) -> Result<()> {
    retry_at(tx, check, now, check.cursor)
}

/// A failed or unknown pass: count it, back off (doubling to five minutes),
/// and keep the walk's place.
fn retry_at(
    tx: &Transaction<'_>,
    check: &Check,
    now: UnixMillis,
    cursor: Option<RepoId>,
) -> Result<()> {
    let attempts = check.attempts.saturating_add(1);
    reschedule(
        tx,
        check,
        now.0.saturating_add(crate::checks::backoff_ms(attempts)),
        attempts,
        cursor,
    )
}

/// The lane could not even ask (no token, GitHub unreachable): the same as an
/// unknown answer, without an identity to compare. Kept separate so the lane
/// does not have to fabricate an observation.
pub fn unreachable(
    tx: &Transaction<'_>,
    check: &Check,
    timing: Timing,
    now: UnixMillis,
    retry_after_ms: Option<i64>,
) -> Result<&'static str> {
    if !is_github_backed(tx, check.tenant)? {
        drop_row(tx, check)?;
        return Ok("not github-backed");
    }
    let synced: Option<Option<i64>> = tx
        .prepare_cached("SELECT synced_ms FROM memberships WHERE tenant_id = ?1 AND user_id = ?2")?
        .query_row(
            params![check.tenant.as_bytes(), check.user.as_bytes()],
            |r| r.get(0),
        )
        .optional()?;
    match synced {
        Some(synced) => {
            let since = synced.unwrap_or(now.0);
            if synced.is_none() {
                tx.execute(
                    "UPDATE memberships SET synced_ms = ?3 WHERE tenant_id = ?1 AND user_id = ?2",
                    params![check.tenant.as_bytes(), check.user.as_bytes(), now.0],
                )?;
            }
            if now.0.saturating_sub(since) >= timing.grace_ms {
                remove_derived(tx, check.tenant, check.user, now, "grace expired")?;
                drop_row(tx, check)?;
                return Ok("removed: grace expired");
            }
        }
        None if check.attempts.saturating_add(1) >= MAX_CANDIDATE_ATTEMPTS => {
            drop_row(tx, check)?;
            return Ok("dropped: unreachable");
        }
        None => {}
    }
    // Honour GitHub's own "later" within a bound; never retry sooner than the
    // ordinary back-off.
    let attempts = check.attempts.saturating_add(1);
    let wait = crate::checks::backoff_ms(attempts).max(
        retry_after_ms
            .unwrap_or(0)
            .min(timing.recheck_ms.max(60_000)),
    );
    reschedule(
        tx,
        check,
        now.0.saturating_add(wait),
        attempts,
        check.cursor,
    )?;
    Ok("kept: unreachable")
}

/// One member as the members list shows it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Source {
    /// The membership was derived from GitHub.
    pub github: bool,
    /// When GitHub last confirmed it.
    pub synced: Option<UnixMillis>,
}

/// Where one membership comes from; `None` when the person is not a member.
pub fn source(conn: &Connection, tenant: TenantId, user: UserId) -> Result<Option<Source>> {
    Ok(conn
        .prepare_cached("SELECT synced_ms FROM memberships WHERE tenant_id = ?1 AND user_id = ?2")?
        .query_row(params![tenant.as_bytes(), user.as_bytes()], |r| {
            r.get::<_, Option<i64>>(0)
        })
        .optional()?
        .map(|synced| Source {
            github: synced.is_some(),
            synced: synced.map(UnixMillis),
        }))
}
