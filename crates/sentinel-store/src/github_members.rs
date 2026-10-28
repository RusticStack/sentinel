//! Derived membership rests on the immutable GitHub id and lapses unless GitHub confirms it in the grace period.
//! A webhook is only a hint, except a signed member_removed, which revokes at once.
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

pub const PROVIDER: &str = "github";

pub const REPOS_PER_STEP: u32 = 25;

pub const MIN_ON_DEMAND_GAP_MS: i64 = 60_000;

/// `next_ms` of a row that owes no check. A finished pass that has nothing left to ask (a person who is
/// not a member, an unreachable candidate that gave up) parks its row here instead of deleting it, so
/// `checked_ms` keeps holding the on-demand gap: deleting the row would let the next sign-in insert a
/// fresh one with `checked_ms = 0` and ask GitHub again at once. Nothing selects a parked row as due.
pub const PARKED_MS: i64 = i64::MAX;

/// Parked rows older than the gap are equivalent to no row; each on-demand enqueue sweeps a few of them.
const PARKED_SWEEP: i64 = 64;

const MAX_TENANTS_PER_SIGN_IN: i64 = 256;

const MAX_CANDIDATE_ATTEMPTS: u32 = 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OrgRole {
    Owner,
    Member,
}

impl OrgRole {
    pub const fn role(self) -> Role {
        match self {
            OrgRole::Owner => Role::TenantAdmin,
            OrgRole::Member => Role::Operator,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Membership {
    Active(OrgRole),
    Absent,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RepoAccess {
    Known(Permissions),
    Unknown,
}

pub const fn repo_permissions(role: &str) -> Permissions {
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

pub fn is_github_backed(conn: &Connection, tenant: TenantId) -> Result<bool> {
    Ok(conn
        .prepare_cached("SELECT membership_source = 1 FROM tenants WHERE id = ?1")?
        .query_row([tenant.as_bytes()], |r| r.get::<_, bool>(0))
        .optional()?
        .unwrap_or(false))
}

/// On a GitHub-backed tenant only the tenant's own service accounts can be edited by hand. Every other
/// id is refused the same way, whether it names a person, an account elsewhere or nothing at all, so the
/// refusal cannot tell an administrator which `usr_` ids exist.
pub(crate) fn require_app_managed(
    conn: &Connection,
    tenant: TenantId,
    target: Option<UserId>,
) -> Result<()> {
    let backed: bool = conn
        .prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM tenants t WHERE t.id = ?1 AND t.membership_source = 1
             AND (?2 IS NULL OR NOT EXISTS(SELECT 1 FROM users u WHERE u.id = ?2
                  AND u.kind = 1 AND u.service_tenant_id = ?1)))",
        )?
        .query_row(
            params![tenant.as_bytes(), target.as_ref().map(UserId::as_bytes)],
            |r| r.get(0),
        )?;
    if backed {
        Err(Error::Forbidden)
    } else {
        Ok(())
    }
}

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

pub(crate) fn installation_released(
    tx: &Transaction<'_>,
    tenant: TenantId,
    actor: Option<UserId>,
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
    apply_backing(tx, tenant, false, actor, false, now)
}

pub const OPEN_TTL_MS: i64 = 5 * 60 * 1000;

/// A pass superseded by a later request writes nothing: its observation may predate that request.
fn superseded(tx: &Transaction<'_>, check: &Check) -> Result<bool> {
    let current: Option<i64> = tx
        .prepare_cached(
            "SELECT seq FROM github_member_checks WHERE tenant_id = ?1 AND user_id = ?2",
        )?
        .query_row(
            params![check.tenant.as_bytes(), check.user.as_bytes()],
            |r| r.get(0),
        )
        .optional()?;
    Ok(current != Some(check.seq))
}

pub fn enqueue_user(tx: &Transaction<'_>, user: UserId, now: UnixMillis) -> Result<usize> {
    tx.prepare_cached(
        "DELETE FROM github_member_checks WHERE (tenant_id, user_id) IN (
            SELECT tenant_id, user_id FROM github_member_checks
            WHERE next_ms = ?1 AND checked_ms <= ?2 - ?3 LIMIT ?4)",
    )?
    .execute(params![
        PARKED_MS,
        now.0,
        MIN_ON_DEMAND_GAP_MS,
        PARKED_SWEEP
    ])?;
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
                    cursor = NULL WHERE tenant_id = ?1 AND next_ms != ?3",
                params![tenant.as_bytes(), now.0, PARKED_MS],
            )?;
        }
    }
    Ok(())
}

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

#[derive(Clone, Copy, Debug)]
pub struct Check {
    pub tenant: TenantId,
    pub user: UserId,
    pub seq: i64,
    pub attempts: u32,
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetRepo {
    pub repo: RepoId,
    pub remote: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    pub installation: u64,
    pub org_id: u64,
    pub org_login: String,
    pub unusable: bool,
    pub github_id: Option<u64>,
    pub member: Option<Role>,
    pub repos: Vec<TargetRepo>,
    pub more: bool,
}

pub fn target(conn: &Connection, check: &Check) -> Result<Option<Target>> {
    type Install = (String, i64, String, bool);
    let install: Option<Install> = conn
        .prepare_cached(
            "SELECT i.external_id, i.account_id, i.account_login,
                    (i.suspended = 1 OR i.permissions_valid = 0)
             FROM installations i JOIN tenants t ON t.id = i.tenant_id
             WHERE i.tenant_id = ?1 AND i.provider = ?2 AND i.account_personal = 0
               AND i.account_id IS NOT NULL AND t.membership_source = 1
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

#[derive(Clone, Copy, Debug)]
pub struct Timing {
    pub recheck_ms: i64,
    pub grace_ms: i64,
}

#[derive(Clone, Debug)]
pub struct Observed {
    pub github_id: Option<u64>,
    pub membership: Membership,
    pub repos: Vec<(RepoId, RepoAccess)>,
    pub complete: bool,
}

pub fn apply(
    tx: &Transaction<'_>,
    check: &Check,
    more_repos: bool,
    observed: &Observed,
    timing: Timing,
    now: UnixMillis,
) -> Result<&'static str> {
    if !is_github_backed(tx, check.tenant)? {
        remove_row(tx, check)?;
        return Ok("not github-backed");
    }
    if superseded(tx, check)? {
        return Ok("superseded");
    }
    let linked: Option<String> = tx
        .prepare_cached(
            "SELECT subject FROM external_identities WHERE provider = ?1 AND user_id = ?2",
        )?
        .query_row(params![PROVIDER, check.user.as_bytes()], |r| r.get(0))
        .optional()?;
    let linked = linked.and_then(|s| s.parse::<u64>().ok());
    if linked != observed.github_id {
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
    if let Some((_, None)) = existing {
        tx.execute(
            "UPDATE memberships SET synced_ms = ?3 WHERE tenant_id = ?1 AND user_id = ?2",
            params![check.tenant.as_bytes(), check.user.as_bytes(), now.0],
        )?;
    }
    let last_confirmed = existing.and_then(|(_, synced)| synced).unwrap_or(now.0);
    let expired = now.0.saturating_sub(last_confirmed) >= timing.grace_ms;

    if observed.github_id.is_none() {
        return match existing {
            None => {
                drop_row(tx, check, now)?;
                Ok("nothing to check")
            }
            Some(_) if expired => {
                remove_derived(tx, check.tenant, check.user, now, "no linked account")?;
                drop_row(tx, check, now)?;
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
            drop_row(tx, check, now)?;
            Ok(if removed {
                "removed: not a member"
            } else {
                "not a member"
            })
        }
        Membership::Unknown => match existing {
            Some(_) if expired => {
                remove_derived(tx, check.tenant, check.user, now, "grace expired")?;
                drop_row(tx, check, now)?;
                Ok("removed: grace expired")
            }
            Some(_) => {
                retry(tx, check, now)?;
                Ok("kept: unknown")
            }
            None if check.attempts.saturating_add(1) >= MAX_CANDIDATE_ATTEMPTS => {
                drop_row(tx, check, now)?;
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
                        drop_row(tx, check, now)?;
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

pub fn finish(tx: &Transaction<'_>, check: &Check) -> Result<()> {
    remove_row(tx, check)
}

/// Deletes the row: the pair is not checkable at all (no target, not GitHub-backed), so no gap is owed.
fn remove_row(tx: &Transaction<'_>, check: &Check) -> Result<()> {
    tx.execute(
        "DELETE FROM github_member_checks WHERE tenant_id = ?1 AND user_id = ?2 AND seq = ?3",
        params![check.tenant.as_bytes(), check.user.as_bytes(), check.seq],
    )?;
    Ok(())
}

/// The pass is over and nothing is owed: park the row and keep the time GitHub was last asked, so repeated
/// on-demand requests still wait out `MIN_ON_DEMAND_GAP_MS`. A signed event for the pair wakes it at once.
fn drop_row(tx: &Transaction<'_>, check: &Check, now: UnixMillis) -> Result<()> {
    tx.execute(
        "UPDATE github_member_checks SET next_ms = ?4, checked_ms = ?5, attempts = 0, cursor = NULL
         WHERE tenant_id = ?1 AND user_id = ?2 AND seq = ?3",
        params![
            check.tenant.as_bytes(),
            check.user.as_bytes(),
            check.seq,
            PARKED_MS,
            now.0
        ],
    )?;
    Ok(())
}

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

pub fn unreachable(
    tx: &Transaction<'_>,
    check: &Check,
    timing: Timing,
    now: UnixMillis,
    retry_after_ms: Option<i64>,
) -> Result<&'static str> {
    if !is_github_backed(tx, check.tenant)? {
        remove_row(tx, check)?;
        return Ok("not github-backed");
    }
    if superseded(tx, check)? {
        return Ok("superseded");
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
                drop_row(tx, check, now)?;
                return Ok("removed: grace expired");
            }
        }
        None if check.attempts.saturating_add(1) >= MAX_CANDIDATE_ATTEMPTS => {
            drop_row(tx, check, now)?;
            return Ok("dropped: unreachable");
        }
        None => {}
    }
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Source {
    pub github: bool,
    pub synced: Option<UnixMillis>,
}

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
