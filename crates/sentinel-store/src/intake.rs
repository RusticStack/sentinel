//! Durable event intake (G02).
//!
//! One authenticated ref update — a generic relay submission or a GitHub
//! `push` — becomes one row here, keyed by the provider's delivery ID scoped
//! to its repository, so redelivery is idempotent and visible. Acceptance
//! happens inside one writer transaction and is acknowledged only after it
//! commits; the controller resolves accepted deliveries asynchronously
//! through [`resolve_due`], bounded by retries, batch size and a per-repo
//! admission bound.
//!
//! Authentication is the caller's: the generic path verifies a repository
//! hook secret with [`authenticate`], the GitHub path verifies the App's
//! webhook signature before this module is reached. Either way the delivery
//! is tenant-owned by the repository row, never by a caller-supplied tenant.

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sentinel_auth::secret::Secret;
use sentinel_core::{DeliveryId, RepoId, TenantId, UnixMillis, UserId};

use crate::registration::Authority;
use crate::{Error, Result, sources};

/// Pending deliveries one repository may hold. Past this the relay is told to
/// back off explicitly; the queue cannot grow without bound.
pub const MAX_PENDING_PER_REPO: i64 = 1024;
/// Resolution attempts before a delivery is settled as failed. Retries are for
/// transient faults, never for a decision.
pub const MAX_ATTEMPTS: u32 = 8;
const BASE_BACKOFF_MS: i64 = 1_000;
const MAX_BACKOFF_MS: i64 = 5 * 60 * 1000;

/// Lifecycle of one delivery. Settled states are terminal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// Accepted and durable; waiting for resolution.
    Pending,
    /// The source was validated; the compiled-run path (G03) consumes it.
    Ready,
    /// Understood and deliberately not a trigger (deletion, foreign event).
    Ignored,
    /// An explicit outcome: the event looked admissible but cannot run.
    Failed,
}

impl State {
    pub const fn code(self) -> i64 {
        match self {
            Self::Pending => 0,
            Self::Ready => 1,
            Self::Ignored => 2,
            Self::Failed => 3,
        }
    }

    const fn decode(code: i64) -> Option<Self> {
        Some(match code {
            0 => Self::Pending,
            1 => Self::Ready,
            2 => Self::Ignored,
            3 => Self::Failed,
            _ => return None,
        })
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Ready => "ready",
            Self::Ignored => "ignored",
            Self::Failed => "failed",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "pending" => Self::Pending,
            "ready" => Self::Ready,
            "ignored" => Self::Ignored,
            "failed" => Self::Failed,
            _ => return None,
        })
    }
}

/// One stored delivery, as read back.
#[derive(Clone, Debug)]
pub struct Delivery {
    pub id: DeliveryId,
    pub tenant: TenantId,
    pub repo: RepoId,
    pub provider: String,
    pub external_id: String,
    pub event: String,
    pub ref_name: Option<String>,
    pub old_sha: Option<String>,
    pub new_sha: Option<String>,
    pub state: State,
    pub reason: Option<String>,
    pub attempts: u32,
    pub received: UnixMillis,
    pub settled: Option<UnixMillis>,
}

/// A new delivery's terms. Bounded and canonical: the store validates shape
/// again, so no caller can persist something the wire contract would refuse.
pub struct NewDelivery<'a> {
    pub provider: &'a str,
    pub external_id: &'a str,
    pub event: &'a str,
    pub ref_name: &'a str,
    pub old_sha: &'a str,
    pub new_sha: &'a str,
}

/// The result of acceptance: exactly one row exists for this identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Accepted {
    /// This call created the row.
    Fresh(DeliveryId),
    /// The identity was already stored, with identical terms.
    Duplicate(DeliveryId),
}

impl Accepted {
    pub const fn id(self) -> DeliveryId {
        match self {
            Self::Fresh(id) | Self::Duplicate(id) => id,
        }
    }
    pub const fn duplicate(self) -> bool {
        matches!(self, Self::Duplicate(_))
    }
}

fn check(delivery: &NewDelivery<'_>) -> Result<()> {
    if delivery.provider.is_empty()
        || delivery.provider.len() > 32
        || delivery.event.is_empty()
        || delivery.event.len() > 64
        || !sentinel_protocol::intake::valid_delivery_id(delivery.external_id)
        || !sentinel_protocol::intake::valid_ref(delivery.ref_name)
        || !sentinel_protocol::intake::valid_sha(delivery.old_sha)
        || !sentinel_protocol::intake::valid_sha(delivery.new_sha)
    {
        return Err(Error::InvalidInput("delivery"));
    }
    Ok(())
}

/// Store one authenticated delivery. Deduplication and the admission bound
/// are decided inside the caller's writer transaction, so acknowledgement
/// cannot precede durability and two redeliveries cannot both be fresh.
pub fn accept(
    tx: &Transaction<'_>,
    repo: RepoId,
    delivery: &NewDelivery<'_>,
    now: UnixMillis,
) -> Result<Accepted> {
    check(delivery)?;
    let tenant = sources::repo_tenant(tx, repo)?;
    let metadata = sources::load_metadata(tx, repo).map_err(|e| match e {
        Error::NotFound => Error::Forbidden,
        other => other,
    })?;
    if metadata.revoked {
        return Err(Error::Forbidden);
    }
    if let Some(existing) = find(tx, tenant, repo, delivery.provider, delivery.external_id)? {
        if existing.ref_name.as_deref() == Some(delivery.ref_name)
            && existing.old_sha.as_deref() == Some(delivery.old_sha)
            && existing.new_sha.as_deref() == Some(delivery.new_sha)
            && existing.event == delivery.event
        {
            return Ok(Accepted::Duplicate(existing.id));
        }
        // One delivery identity, two different events: a sender bug, refused
        // rather than silently collapsing the second.
        return Err(Error::Conflict);
    }
    let pending: i64 = tx
        .prepare_cached("SELECT count(*) FROM webhook_deliveries WHERE repo_id = ?1 AND state = 0")?
        .query_row([repo.as_bytes()], |r| r.get(0))?;
    if pending >= MAX_PENDING_PER_REPO {
        return Err(Error::Overloaded);
    }
    let id = DeliveryId::new();
    tx.execute(
        "INSERT INTO webhook_deliveries(id, tenant_id, repo_id, provider, external_id,
            event, ref_name, old_sha, new_sha, state, received_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 0, ?10)",
        params![
            id.as_bytes(),
            tenant.as_bytes(),
            repo.as_bytes(),
            delivery.provider,
            delivery.external_id,
            delivery.event,
            delivery.ref_name,
            delivery.old_sha,
            delivery.new_sha,
            now.0
        ],
    )?;
    Ok(Accepted::Fresh(id))
}

fn find(
    conn: &Connection,
    tenant: TenantId,
    repo: RepoId,
    provider: &str,
    external_id: &str,
) -> Result<Option<Delivery>> {
    let row = conn
        .prepare_cached(
            "SELECT id FROM webhook_deliveries
             WHERE tenant_id = ?1 AND repo_id = ?2 AND provider = ?3 AND external_id = ?4",
        )?
        .query_row(
            params![tenant.as_bytes(), repo.as_bytes(), provider, external_id],
            |r| r.get::<_, [u8; 16]>(0),
        )
        .optional()?;
    match row {
        Some(bytes) => {
            let id = DeliveryId::from_bytes(bytes).map_err(|_| Error::Corrupt("delivery id"))?;
            get(conn, id).map(Some)
        }
        None => Ok(None),
    }
}

/// Resolve which repository an authenticated hook secret belongs to. `None`
/// is an unknown secret (revoked or never issued); the caller maps that to a
/// 401 without distinguishing the two. The tenant must still be active.
pub fn authenticate(conn: &Connection, presented: &Secret) -> Result<Option<(TenantId, RepoId)>> {
    let row = conn
        .prepare_cached(
            "SELECT t.tenant_id, t.repo_id FROM source_intake_tokens t
             JOIN tenants n ON n.id = t.tenant_id AND n.active = 1
             WHERE t.token_digest = ?1",
        )?
        .query_row([presented.digest().0], |r| {
            Ok((r.get::<_, [u8; 16]>(0)?, r.get::<_, [u8; 16]>(1)?))
        })
        .optional()?;
    let Some((tenant, repo)) = row else {
        return Ok(None);
    };
    Ok(Some((
        TenantId::from_bytes(tenant).map_err(|_| Error::Corrupt("tenant_id"))?,
        RepoId::from_bytes(repo).map_err(|_| Error::Corrupt("repo_id"))?,
    )))
}

/// The format a hook secret is presented and printed in: a distinguishable
/// prefix over the 64 lower-case hex characters of the secret itself.
pub fn hook_token_text(secret: &Secret) -> String {
    let mut text = String::with_capacity(
        sentinel_protocol::intake::HOOK_TOKEN_PREFIX.len() + Secret::TEXT_LEN,
    );
    text.push_str(sentinel_protocol::intake::HOOK_TOKEN_PREFIX);
    secret.expose(&mut text);
    text
}

pub fn hook_token_parse(text: &str) -> Option<Secret> {
    Secret::parse(text.strip_prefix(sentinel_protocol::intake::HOOK_TOKEN_PREFIX)?)
}

/// Issue (or rotate) the repository's hook secret. One active secret per
/// repository: issuing replaces the previous digest in the same transaction,
/// so a rotated secret is unusable the moment this commits.
pub fn issue_token(
    tx: &Transaction<'_>,
    authority: Authority,
    repo: RepoId,
    now: UnixMillis,
) -> Result<Secret> {
    let tenant = tenant_admin_of(tx, authority, repo)?;
    // A secret for a repository that cannot run is a footgun, not a feature.
    if sources::load_metadata(tx, repo)?.revoked {
        return Err(Error::NotFound);
    }
    let secret = Secret::generate();
    tx.execute(
        "DELETE FROM source_intake_tokens WHERE repo_id = ?1",
        [repo.as_bytes()],
    )?;
    tx.execute(
        "INSERT INTO source_intake_tokens(token_digest, repo_id, tenant_id, created_ms)
         VALUES (?1, ?2, ?3, ?4)",
        params![secret.digest().0, repo.as_bytes(), tenant.as_bytes(), now.0],
    )?;
    audit(tx, tenant, repo, authority.actor(), "hook-token", now)?;
    Ok(secret)
}

/// Revoke the repository's hook secret. Nothing to revoke is `NotFound`.
pub fn revoke_token(
    tx: &Transaction<'_>,
    authority: Authority,
    repo: RepoId,
    now: UnixMillis,
) -> Result<()> {
    let tenant = tenant_admin_of(tx, authority, repo)?;
    let removed = tx.execute(
        "DELETE FROM source_intake_tokens WHERE repo_id = ?1",
        [repo.as_bytes()],
    )?;
    if removed == 0 {
        return Err(Error::NotFound);
    }
    audit(
        tx,
        tenant,
        repo,
        authority.actor(),
        "hook-token-revoked",
        now,
    )
}

/// The tenant that owns the repository, requiring tenant administration for a
/// credentialed caller. Host-local callers hold the database file already.
fn tenant_admin_of(tx: &Transaction<'_>, authority: Authority, repo: RepoId) -> Result<TenantId> {
    match authority.principal() {
        Some(principal) => {
            let tenant = crate::auth::require_repo(
                tx,
                principal,
                repo,
                sentinel_core::auth::Permissions::READ,
            )?;
            crate::auth::require_tenant_admin(tx, principal, tenant)?;
            Ok(tenant)
        }
        None => sources::repo_tenant(tx, repo),
    }
}

/// When the repository's hook secret was issued, if one exists. Metadata only.
pub fn token_issued(conn: &Connection, repo: RepoId) -> Result<Option<UnixMillis>> {
    Ok(conn
        .prepare_cached("SELECT created_ms FROM source_intake_tokens WHERE repo_id = ?1")?
        .query_row([repo.as_bytes()], |r| r.get::<_, i64>(0))
        .optional()?
        .map(UnixMillis))
}

/// The tenant-owned repository behind a GitHub installation and immutable
/// repository ID. Unbound, suspended or revoked authorizes nothing.
pub fn github_target(
    conn: &Connection,
    installation_external_id: &str,
    forge_repo_id: i64,
) -> Result<(TenantId, RepoId)> {
    let row = conn
        .prepare_cached(
            "SELECT b.tenant_id, b.repo_id FROM source_bindings b
             JOIN installations i ON i.id = b.installation_id
                AND i.tenant_id = b.tenant_id AND i.provider = 'github'
                AND i.external_id = ?1 AND i.suspended = 0
             JOIN tenants t ON t.id = b.tenant_id AND t.active = 1
             WHERE b.forge_repo_id = ?2 AND b.revoked = 0",
        )?
        .query_row(params![installation_external_id, forge_repo_id], |r| {
            Ok((r.get::<_, [u8; 16]>(0)?, r.get::<_, [u8; 16]>(1)?))
        })
        .optional()?;
    let Some((tenant, repo)) = row else {
        return Err(Error::NotFound);
    };
    Ok((
        TenantId::from_bytes(tenant).map_err(|_| Error::Corrupt("tenant_id"))?,
        RepoId::from_bytes(repo).map_err(|_| Error::Corrupt("repo_id"))?,
    ))
}

/// One row, still raw: decode is where invalid blobs become typed errors.
type Fields = (
    [u8; 16],
    [u8; 16],
    [u8; 16],
    String,
    String,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    i64,
    Option<String>,
    i64,
    i64,
    Option<i64>,
);

fn map_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Fields> {
    Ok((
        r.get(0)?,
        r.get(1)?,
        r.get(2)?,
        r.get(3)?,
        r.get(4)?,
        r.get(5)?,
        r.get(6)?,
        r.get(7)?,
        r.get(8)?,
        r.get(9)?,
        r.get(10)?,
        r.get(11)?,
        r.get(12)?,
        r.get(13)?,
    ))
}

fn decode(row: Fields) -> Result<Delivery> {
    let (
        id,
        tenant,
        repo,
        provider,
        external_id,
        event,
        ref_name,
        old_sha,
        new_sha,
        state,
        reason,
        attempts,
        received,
        settled,
    ) = row;
    Ok(Delivery {
        id: DeliveryId::from_bytes(id).map_err(|_| Error::Corrupt("delivery id"))?,
        tenant: TenantId::from_bytes(tenant).map_err(|_| Error::Corrupt("tenant_id"))?,
        repo: RepoId::from_bytes(repo).map_err(|_| Error::Corrupt("repo_id"))?,
        provider,
        external_id,
        event,
        ref_name,
        old_sha,
        new_sha,
        state: State::decode(state).ok_or(Error::Corrupt("delivery state"))?,
        reason,
        attempts: u32::try_from(attempts).map_err(|_| Error::Corrupt("delivery attempts"))?,
        received: UnixMillis(received),
        settled: settled.map(UnixMillis),
    })
}

/// Read one delivery by ID. Trusted internal: the caller has already decided
/// who may see it (the host-local CLI, or the resolution lane).
pub fn get(conn: &Connection, id: DeliveryId) -> Result<Delivery> {
    let sql = "SELECT id, tenant_id, repo_id, provider, external_id, event, ref_name, old_sha, new_sha, state, reason, attempts, received_ms, settled_ms FROM webhook_deliveries WHERE id = ?1";
    let row = conn
        .prepare_cached(sql)?
        .query_row([id.as_bytes()], map_row)
        .optional()?
        .ok_or(Error::NotFound)?;
    decode(row)
}

/// Newest deliveries of one repository, optionally one state only.
pub fn list(
    conn: &Connection,
    tenant: TenantId,
    repo: RepoId,
    state: Option<State>,
    limit: u16,
) -> Result<Vec<Delivery>> {
    if !(1..=100).contains(&limit) {
        return Err(Error::InvalidInput("page size"));
    }
    let sql = "SELECT id, tenant_id, repo_id, provider, external_id, event, ref_name, old_sha, new_sha, state, reason, attempts, received_ms, settled_ms FROM webhook_deliveries
         WHERE tenant_id = ?1 AND repo_id = ?2 AND (?3 IS NULL OR state = ?3)
         ORDER BY received_ms DESC, id LIMIT ?4";
    let mut stmt = conn.prepare_cached(sql)?;
    let rows = stmt.query_map(
        params![
            tenant.as_bytes(),
            repo.as_bytes(),
            state.map(State::code),
            limit
        ],
        map_row,
    )?;
    rows.map(|row| decode(row?)).collect()
}

/// Deliveries whose next attempt is due, oldest first.
pub fn due(conn: &Connection, now: UnixMillis, limit: u16) -> Result<Vec<Delivery>> {
    let sql = "SELECT id, tenant_id, repo_id, provider, external_id, event, ref_name, old_sha, new_sha, state, reason, attempts, received_ms, settled_ms FROM webhook_deliveries
         WHERE state = 0 AND (next_attempt_ms IS NULL OR next_attempt_ms <= ?1)
         ORDER BY received_ms, id LIMIT ?2";
    let mut stmt = conn.prepare_cached(sql)?;
    let rows = stmt.query_map(params![now.0, limit], map_row)?;
    rows.map(|row| decode(row?)).collect()
}

/// What resolution decided about one delivery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resolution {
    Ready,
    Ignored(&'static str),
    Failed(&'static str),
}

impl Resolution {
    pub fn describe(self) -> String {
        match self {
            Self::Ready => "ready".into(),
            Self::Ignored(reason) => format!("ignored:{reason}"),
            Self::Failed(reason) => format!("failed:{reason}"),
        }
    }
}

/// Revalidate a pending delivery against the source binding as it is *now*:
/// intake authorized it, but a binding can be revoked or narrowed between
/// acceptance and resolution, and a delivery that cannot be fetched, or is
/// not a trigger, must not run.
pub fn validate(conn: &Connection, delivery: &Delivery) -> Result<Resolution> {
    if sources::repo_tenant(conn, delivery.repo).is_err() {
        return Ok(Resolution::Failed("tenant_suspended"));
    }
    let metadata = match sources::load_metadata(conn, delivery.repo) {
        Ok(metadata) => metadata,
        Err(Error::NotFound) => return Ok(Resolution::Failed("binding_revoked")),
        Err(e) => return Err(e),
    };
    if metadata.revoked {
        return Ok(Resolution::Failed("binding_revoked"));
    }
    let (Some(ref_name), Some(new_sha)) = (&delivery.ref_name, &delivery.new_sha) else {
        return Ok(Resolution::Ignored("no_ref"));
    };
    if sentinel_protocol::intake::is_zero_sha(new_sha) {
        return Ok(Resolution::Ignored("ref_deleted"));
    }
    if !metadata.binding.allows(ref_name) {
        return Ok(Resolution::Failed("ref_not_allowed"));
    }
    Ok(Resolution::Ready)
}

/// Settle one pending delivery. A settled delivery is final: the guarded
/// update reports a conflict rather than rewriting an outcome.
pub fn settle(
    tx: &Transaction<'_>,
    id: DeliveryId,
    resolution: Resolution,
    now: UnixMillis,
) -> Result<()> {
    let (state, reason) = match resolution {
        Resolution::Ready => (State::Ready, None),
        Resolution::Ignored(reason) => (State::Ignored, Some(reason)),
        Resolution::Failed(reason) => (State::Failed, Some(reason)),
    };
    let changed = tx.execute(
        "UPDATE webhook_deliveries SET state = ?2, reason = ?3, settled_ms = ?4
         WHERE id = ?1 AND state = 0",
        params![id.as_bytes(), state.code(), reason, now.0],
    )?;
    if changed != 1 {
        return Err(Error::Conflict);
    }
    Ok(())
}

/// Schedule another attempt with capped exponential backoff, or fail the
/// delivery once the attempt budget is spent. The reason is always explicit.
pub fn retry(tx: &Transaction<'_>, id: DeliveryId, now: UnixMillis) -> Result<()> {
    let attempts: i64 = tx
        .prepare_cached("SELECT attempts FROM webhook_deliveries WHERE id = ?1 AND state = 0")?
        .query_row([id.as_bytes()], |r| r.get(0))
        .optional()?
        .ok_or(Error::Conflict)?;
    let next = u32::try_from(attempts.saturating_add(1)).unwrap_or(u32::MAX);
    if next >= MAX_ATTEMPTS {
        return settle(tx, id, Resolution::Failed("resolution_attempts"), now);
    }
    let changed = tx.execute(
        "UPDATE webhook_deliveries SET attempts = ?2, next_attempt_ms = ?3
         WHERE id = ?1 AND state = 0",
        params![
            id.as_bytes(),
            next as i64,
            now.0.saturating_add(backoff_ms(next))
        ],
    )?;
    if changed != 1 {
        return Err(Error::Conflict);
    }
    Ok(())
}

/// Milliseconds to wait before attempt `attempts` (1-based): doubling from
/// one second, capped at five minutes.
pub fn backoff_ms(attempts: u32) -> i64 {
    BASE_BACKOFF_MS
        .saturating_mul(1i64 << attempts.min(20))
        .min(MAX_BACKOFF_MS)
}

/// One pass of the resolution lane: validate and settle every due delivery.
/// Runs inside one writer transaction; the caller bounds the batch.
pub fn resolve_due(
    tx: &Transaction<'_>,
    now: UnixMillis,
    limit: u16,
) -> Result<Vec<(DeliveryId, Resolution)>> {
    let due = due(tx, now, limit)?;
    let mut settled = Vec::with_capacity(due.len());
    for delivery in due {
        let current = match get(tx, delivery.id) {
            Ok(current) => current,
            Err(Error::NotFound) => continue,
            Err(e) => return Err(e),
        };
        if current.state != State::Pending {
            continue;
        }
        let resolution = validate(tx, &current)?;
        settle(tx, current.id, resolution, now)?;
        settled.push((current.id, resolution));
    }
    Ok(settled)
}

/// Delete settled deliveries older than `before`, in bounded batches. Never
/// touches a pending row: an unresolved event is work, not history.
pub fn purge_settled(tx: &Transaction<'_>, before: UnixMillis, limit: u32) -> Result<usize> {
    Ok(tx.execute(
        "DELETE FROM webhook_deliveries WHERE id IN (
            SELECT id FROM webhook_deliveries
            WHERE state != 0 AND settled_ms <= ?1
            ORDER BY settled_ms LIMIT ?2)",
        params![before.0, limit],
    )?)
}

fn audit(
    tx: &Transaction<'_>,
    tenant: TenantId,
    repo: RepoId,
    actor: Option<UserId>,
    action: &str,
    now: UnixMillis,
) -> Result<()> {
    let version = sources::load_metadata(tx, repo)
        .map(|m| m.version)
        .unwrap_or(1) as i64;
    tx.execute(
        "INSERT INTO source_audit(tenant_id, repo_id, version, actor, action, at_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            tenant.as_bytes(),
            repo.as_bytes(),
            version,
            actor.map(|a| *a.as_bytes()),
            action,
            now.0
        ],
    )?;
    Ok(())
}
