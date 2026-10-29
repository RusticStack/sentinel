use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sentinel_auth::secret::{Digest, Secret};
use sentinel_core::{PoolId, TokenId, UnixMillis, UserId, WorkerId};
use sentinel_protocol::negotiate::{Arch, Capabilities, Negotiated, ProtocolVersion};

use crate::{
    Error, Result,
    auth::Authority,
    local_auth::{Event, audit},
};

const DAY_MS: i64 = 24 * 60 * 60 * 1000;
pub const DEFAULT_ENROLLMENT_MS: i64 = 60 * 60 * 1000;
pub const MAX_ENROLLMENT_MS: i64 = DAY_MS;
pub const SEEN_RECORD_INTERVAL_MS: i64 = 60 * 1000;

/// How long after a redemption the same machine may present the same secret again and be told the
/// same answer: the response to the first call can be lost on the way back, and the machine retries
/// with the identity it already holds. Any other presentation of a spent secret is refused.
pub const REPLAY_WINDOW_MS: i64 = 10 * 60 * 1000;

/// Operator priority bounds: higher is preferred, zero is neutral.
pub const PRIORITY_MIN: i32 = -100;
pub const PRIORITY_MAX: i32 = 100;

/// A Tailcat node key as stored: the 32 bytes behind `nodekey:<64 hex>`.
pub type NodeKey = [u8; 32];

/// Parse the `nodekey:<64 hex>` spelling the helper and the allow list use.
pub fn parse_node_key(text: &str) -> Option<NodeKey> {
    let body = text.trim().strip_prefix("nodekey:")?.as_bytes();
    if body.len() != 64 {
        return None;
    }
    let mut key = [0u8; 32];
    for (slot, pair) in key.iter_mut().zip(body.chunks_exact(2)) {
        let pair = std::str::from_utf8(pair).ok()?;
        *slot = u8::from_str_radix(pair, 16).ok()?;
    }
    Some(key)
}

/// What the controller approves for a host: ceilings below the host's own report and an operator
/// priority. A worker never states these; they are written at enrollment or by `set_policy`.
/// `None` means the host's report is the only limit.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HostPolicy {
    pub cpu_millis: Option<i64>,
    pub memory_bytes: Option<i64>,
    pub disk_bytes: Option<i64>,
    pub priority: i32,
}

impl HostPolicy {
    fn validate(&self) -> Result<()> {
        let positive = |value: Option<i64>| value.is_none_or(|v| v > 0);
        if !positive(self.cpu_millis) || !positive(self.memory_bytes) || !positive(self.disk_bytes)
        {
            return Err(Error::InvalidInput("host ceiling"));
        }
        if !(PRIORITY_MIN..=PRIORITY_MAX).contains(&self.priority) {
            return Err(Error::InvalidInput("host priority"));
        }
        Ok(())
    }

    /// A reported size under the ceilings. An unreported disk (zero) becomes the disk ceiling: an
    /// approved limit is a real limit even for a worker that never measured its own.
    pub fn clamp(&self, cpu_millis: i64, memory_bytes: i64, disk_bytes: i64) -> (i64, i64, i64) {
        let cpu = self.cpu_millis.map_or(cpu_millis, |c| cpu_millis.min(c));
        let memory = self
            .memory_bytes
            .map_or(memory_bytes, |m| memory_bytes.min(m));
        let disk = match self.disk_bytes {
            None => disk_bytes,
            Some(d) if disk_bytes == 0 => d,
            Some(d) => disk_bytes.min(d),
        };
        (cpu, memory, disk)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Worker {
    pub id: WorkerId,
    pub pool: PoolId,
    pub fingerprint: Digest,
    pub name: String,
    pub negotiated: Negotiated,
    pub enrolled: UnixMillis,
    pub last_seen: Option<UnixMillis>,
    pub software: Option<String>,
    pub policy: HostPolicy,
    pub node_key: Option<NodeKey>,
    pub uninstall_requested: Option<UnixMillis>,
}

pub struct Enrollment {
    pub id: TokenId,
    pub secret: Secret,
    pub pool: PoolId,
    pub expires: UnixMillis,
    pub policy: HostPolicy,
    pub tailcat: bool,
}

/// The terms an administrator chooses for one enrollment.
#[derive(Clone, Copy, Debug)]
pub struct EnrollmentTerms {
    pub pool: PoolId,
    pub lifetime_ms: i64,
    pub policy: HostPolicy,
    /// Redemption must present the worker's Tailcat node key (the generated default); `false` is
    /// the direct-TLS fallback, where a node key is refused.
    pub tailcat: bool,
}

pub fn issue_enrollment(
    tx: &Transaction<'_>,
    authority: Authority,
    pool: PoolId,
    lifetime_ms: i64,
    now: UnixMillis,
) -> Result<Enrollment> {
    issue_enrollment_with(
        tx,
        authority,
        EnrollmentTerms {
            pool,
            lifetime_ms,
            policy: HostPolicy::default(),
            tailcat: false,
        },
        now,
    )
}

pub fn issue_enrollment_with(
    tx: &Transaction<'_>,
    authority: Authority,
    terms: EnrollmentTerms,
    now: UnixMillis,
) -> Result<Enrollment> {
    authority.require_platform(tx)?;
    let EnrollmentTerms {
        pool,
        lifetime_ms,
        policy,
        tailcat,
    } = terms;
    if !(1..=MAX_ENROLLMENT_MS).contains(&lifetime_ms) {
        return Err(Error::InvalidInput("enrollment lifetime"));
    }
    policy.validate()?;
    let active: bool = tx
        .prepare_cached("SELECT EXISTS(SELECT 1 FROM pools WHERE id = ?1 AND active = 1)")?
        .query_row([pool.as_bytes()], |r| r.get(0))?;
    if !active {
        return Err(Error::NotFound);
    }
    let id = TokenId::new();
    let secret = Secret::generate();
    let expires = UnixMillis(now.0.saturating_add(lifetime_ms));
    tx.execute(
        "INSERT INTO worker_enrollments(token_digest, id, pool_id, created_by, created_ms, expires_ms,
                cpu_ceiling_millis, memory_ceiling_bytes, disk_ceiling_bytes, priority, tailcat)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            secret.digest().0,
            id.as_bytes(),
            pool.as_bytes(),
            authority.actor().as_ref().map(UserId::as_bytes),
            now.0,
            expires.0,
            policy.cpu_millis,
            policy.memory_bytes,
            policy.disk_bytes,
            policy.priority,
            tailcat
        ],
    )?;
    audit(
        tx,
        Event::WorkerEnrollmentIssued,
        authority.actor(),
        None,
        authority.host_local(),
        None,
    )?;
    Ok(Enrollment {
        id,
        secret,
        pool,
        expires,
        policy,
        tailcat,
    })
}

pub fn revoke_enrollment(
    tx: &Transaction<'_>,
    authority: Authority,
    id: TokenId,
    now: UnixMillis,
) -> Result<()> {
    authority.require_platform(tx)?;
    let changed = tx.execute(
        "UPDATE worker_enrollments SET revoked_ms = ?2
         WHERE id = ?1 AND revoked_ms IS NULL AND redeemed_ms IS NULL",
        params![id.as_bytes(), now.0],
    )?;
    if changed == 0 {
        return Err(Error::NotFound);
    }
    audit(
        tx,
        Event::WorkerEnrollmentRevoked,
        authority.actor(),
        None,
        authority.host_local(),
        Some(&id.to_string()),
    )
}

/// Where an enrollment stands. `Expired` is derived from the clock; the others are stored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnrollmentState {
    Pending,
    Redeemed,
    Revoked,
    Expired,
}

/// An enrollment as an administrator sees it: the terms, never the secret (only its digest is stored).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EnrollmentStatus {
    pub id: TokenId,
    pub pool: PoolId,
    pub created: UnixMillis,
    pub expires: UnixMillis,
    pub policy: HostPolicy,
    pub tailcat: bool,
    pub state: EnrollmentState,
}

fn enrollment_status_of(
    conn: &Connection,
    id: TokenId,
    now: UnixMillis,
) -> Result<EnrollmentStatus> {
    let (pool, created, expires, redeemed, revoked, policy, tailcat) = conn
        .prepare_cached(
            "SELECT pool_id, created_ms, expires_ms, redeemed_ms, revoked_ms,
                    cpu_ceiling_millis, memory_ceiling_bytes, disk_ceiling_bytes, priority, tailcat
             FROM worker_enrollments WHERE id = ?1",
        )?
        .query_row([id.as_bytes()], |r| {
            Ok((
                r.get::<_, PoolBytes>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, Option<i64>>(3)?,
                r.get::<_, Option<i64>>(4)?,
                HostPolicy {
                    cpu_millis: r.get(5)?,
                    memory_bytes: r.get(6)?,
                    disk_bytes: r.get(7)?,
                    priority: r.get(8)?,
                },
                r.get::<_, bool>(9)?,
            ))
        })
        .optional()?
        .ok_or(Error::NotFound)?;
    let state = if revoked.is_some() {
        EnrollmentState::Revoked
    } else if redeemed.is_some() {
        EnrollmentState::Redeemed
    } else if expires <= now.0 {
        EnrollmentState::Expired
    } else {
        EnrollmentState::Pending
    };
    Ok(EnrollmentStatus {
        id,
        pool: PoolId::from_bytes(pool).map_err(|_| Error::Corrupt("pool id"))?,
        created: UnixMillis(created),
        expires: UnixMillis(expires),
        policy,
        tailcat,
        state,
    })
}

/// Read one enrollment's terms and state (platform administration only).
pub fn enrollment_status(
    conn: &Connection,
    authority: Authority,
    id: TokenId,
    now: UnixMillis,
) -> Result<EnrollmentStatus> {
    authority.require_platform(conn)?;
    enrollment_status_of(conn, id, now)
}

/// The most enrollments one listing returns.
pub const ENROLLMENT_PAGE_MAX: u16 = 200;

/// Worker enrollments newest first, optionally for one pool, with the terms and state but never the
/// secret (only its digest is stored). `before` is the `created` time of the last row of the
/// previous page (platform administration only).
pub fn list_enrollments(
    conn: &Connection,
    authority: Authority,
    pool: Option<PoolId>,
    before: Option<UnixMillis>,
    limit: u16,
    now: UnixMillis,
) -> Result<Vec<EnrollmentStatus>> {
    authority.require_platform(conn)?;
    let limit = i64::from(limit.clamp(1, ENROLLMENT_PAGE_MAX));
    let mut stmt = conn.prepare_cached(
        "SELECT id FROM worker_enrollments
         WHERE (?1 IS NULL OR pool_id = ?1) AND (?2 IS NULL OR created_ms < ?2)
         ORDER BY created_ms DESC, id DESC LIMIT ?3",
    )?;
    let ids = stmt
        .query_map(
            params![
                pool.map(|p| p.as_bytes().to_vec()),
                before.map(|t| t.0),
                limit
            ],
            |r| r.get::<_, PoolBytes>(0),
        )?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ids.into_iter()
        .map(|bytes| {
            let id = TokenId::from_bytes(bytes).map_err(|_| Error::Corrupt("enrollment id"))?;
            enrollment_status_of(conn, id, now)
        })
        .collect()
}

/// Record that the bootstrap script of a *pending* enrollment was handed out, and return the terms
/// it was rendered for, in one transaction: a spent, revoked or expired enrollment is `Conflict`
/// and leaves no row, so a script is never issued for an enrollment that can no longer be redeemed.
pub fn note_bootstrap_download(
    tx: &Transaction<'_>,
    authority: Authority,
    id: TokenId,
    now: UnixMillis,
) -> Result<EnrollmentStatus> {
    authority.require_platform(tx)?;
    let status = enrollment_status_of(tx, id, now)?;
    if status.state != EnrollmentState::Pending {
        return Err(Error::Conflict);
    }
    audit(
        tx,
        Event::WorkerBootstrapDownloaded,
        authority.actor(),
        None,
        authority.host_local(),
        Some(&id.to_string()),
    )?;
    Ok(status)
}

#[derive(Clone, Debug)]
pub struct Presentation<'a> {
    pub worker: WorkerId,
    pub fingerprint: Digest,
    pub name: &'a str,
    pub negotiated: Negotiated,
}

pub fn enroll(
    tx: &Transaction<'_>,
    presented: &Secret,
    presentation: Presentation<'_>,
    now: UnixMillis,
) -> Result<Worker> {
    redeem(tx, presented, presentation, now)?.ok_or(Error::NotFound)
}

/// Who a refused enrollment is charged to: a hash of the source key, or `UNATTRIBUTED`.
pub type Peer = [u8; 16];
pub const UNATTRIBUTED: Peer = [0; 16];

/// Refusals are counted per hour; past these caps an attempt is counted but writes no audit row.
pub const REFUSAL_WINDOW_MS: i64 = 60 * 60 * 1000;
pub const REFUSAL_ROWS_PER_PEER: i64 = 5;
pub const REFUSAL_ROWS_PER_WINDOW: i64 = 50;
pub const REFUSAL_PEERS_PER_WINDOW: i64 = 64;
const REFUSAL_KEEP_MS: i64 = 7 * DAY_MS;

const REDEEMABLE: &str =
    "SELECT e.pool_id FROM worker_enrollments e JOIN pools p ON p.id = e.pool_id
             WHERE e.token_digest = ?1 AND e.redeemed_ms IS NULL AND e.revoked_ms IS NULL
             AND e.expires_ms > ?2 AND p.active = 1";

/// Whether `presented` would redeem right now. A read: it records nothing, so the controller can let a
/// secret that is still good through without charging it to the refusal budget.
pub fn redeemable(conn: &Connection, presented: &Secret, now: UnixMillis) -> Result<bool> {
    Ok(conn
        .prepare_cached(REDEEMABLE)?
        .query_row(params![presented.digest().0, now.0], |_| Ok(()))
        .optional()?
        .is_some())
}

// Refusal is Ok(None), not Err: an Err would roll back the audit row a committing caller must keep.
pub fn redeem(
    tx: &Transaction<'_>,
    presented: &Secret,
    presentation: Presentation<'_>,
    now: UnixMillis,
) -> Result<Option<Worker>> {
    redeem_from(tx, presented, presentation, now, UNATTRIBUTED)
}

/// `redeem` with the refusal charged to `peer`, so one peer's guesses cannot use up the audit budget.
pub fn redeem_from(
    tx: &Transaction<'_>,
    presented: &Secret,
    presentation: Presentation<'_>,
    now: UnixMillis,
    peer: Peer,
) -> Result<Option<Worker>> {
    redeem_bound_from(tx, presented, presentation, None, now, peer)
}

/// Redeem an enrollment, binding the TLS fingerprint and, when the enrollment is a Tailcat one, the
/// worker's node key to the new identity in the same transaction that spends the enrollment. An
/// enrollment that wants a node key refuses a redemption without one and the reverse, leaving it
/// unspent for the real machine. A fingerprint or node key already bound to any worker (revoked
/// ones included) is `Conflict`, also leaving the enrollment unspent.
pub fn redeem_bound(
    tx: &Transaction<'_>,
    presented: &Secret,
    presentation: Presentation<'_>,
    node_key: Option<NodeKey>,
    now: UnixMillis,
) -> Result<Option<Worker>> {
    redeem_bound_from(tx, presented, presentation, node_key, now, UNATTRIBUTED)
}

/// `redeem_bound` with the refusal charged to `peer` (see `record_refusal`).
pub fn redeem_bound_from(
    tx: &Transaction<'_>,
    presented: &Secret,
    presentation: Presentation<'_>,
    node_key: Option<NodeKey>,
    now: UnixMillis,
    peer: Peer,
) -> Result<Option<Worker>> {
    if presentation.name.is_empty()
        || presentation.name.len() > 128
        || presentation.name.chars().any(char::is_control)
    {
        return Err(Error::InvalidInput("worker name"));
    }
    let digest = presented.digest();
    let terms: Option<(PoolBytes, HostPolicy, bool)> = tx
        .prepare_cached(
            "SELECT e.pool_id, e.cpu_ceiling_millis, e.memory_ceiling_bytes, e.disk_ceiling_bytes,
                    e.priority, e.tailcat
             FROM worker_enrollments e JOIN pools p ON p.id = e.pool_id
             WHERE e.token_digest = ?1 AND e.redeemed_ms IS NULL AND e.revoked_ms IS NULL
             AND e.expires_ms > ?2 AND p.active = 1",
        )?
        .query_row(params![digest.0, now.0], |r| {
            Ok((
                r.get::<_, PoolBytes>(0)?,
                HostPolicy {
                    cpu_millis: r.get(1)?,
                    memory_bytes: r.get(2)?,
                    disk_bytes: r.get(3)?,
                    priority: r.get(4)?,
                },
                r.get::<_, bool>(5)?,
            ))
        })
        .optional()?;
    let Some((pool, policy, _)) = terms.filter(|(_, _, tailcat)| *tailcat == node_key.is_some())
    else {
        record_refusal(tx, peer, now)?;
        return Ok(None);
    };
    let pool = PoolId::from_bytes(pool).map_err(|_| Error::Corrupt("pool id"))?;
    let inserted = tx.execute(
        "INSERT INTO workers(id, pool_id, fingerprint, name, arch, capabilities, protocol, enrolled_ms,
                cpu_ceiling_millis, memory_ceiling_bytes, disk_ceiling_bytes, priority, node_key)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        params![
            presentation.worker.as_bytes(),
            pool.as_bytes(),
            presentation.fingerprint.0,
            presentation.name,
            arch_name(presentation.negotiated.arch),
            presentation.negotiated.capabilities.0 as i64,
            i64::from(presentation.negotiated.protocol.0),
            now.0,
            policy.cpu_millis,
            policy.memory_bytes,
            policy.disk_bytes,
            policy.priority,
            node_key.as_ref().map(<[u8; 32]>::as_slice)
        ],
    );
    // Leave the enrollment unspent on a conflict so the real machine can still redeem it.
    if let Err(rusqlite::Error::SqliteFailure(code, _)) = &inserted
        && code.code == rusqlite::ErrorCode::ConstraintViolation
    {
        return Err(Error::Conflict);
    }
    inserted?;
    tx.execute(
        "UPDATE worker_enrollments SET redeemed_ms = ?2, redeemed_worker = ?3 WHERE token_digest = ?1",
        params![digest.0, now.0, presentation.worker.as_bytes()],
    )?;
    audit(
        tx,
        Event::WorkerEnrolled,
        None,
        None,
        false,
        Some(presentation.name),
    )?;
    Ok(Some(Worker {
        id: presentation.worker,
        pool,
        fingerprint: presentation.fingerprint,
        name: presentation.name.to_owned(),
        negotiated: presentation.negotiated,
        enrolled: now,
        last_seen: None,
        software: None,
        policy,
        node_key,
        uninstall_requested: None,
    }))
}

// Every refusal is counted; only the first few per peer and per window also write an audit row, and the
// first refusal of a later window writes one row summarising the counted-only ones before it.
fn record_refusal(tx: &Transaction<'_>, peer: Peer, now: UnixMillis) -> Result<()> {
    let window = now.0.div_euclid(REFUSAL_WINDOW_MS) * REFUSAL_WINDOW_MS;
    let (unsummarized, windows): (i64, i64) = tx
        .prepare_cached(
            "SELECT COALESCE(SUM(suppressed), 0), COUNT(DISTINCT window_ms)
             FROM worker_enrollment_refusals WHERE window_ms < ?1 AND suppressed > 0 AND summarized = 0",
        )?
        .query_row([window], |r| Ok((r.get(0)?, r.get(1)?)))?;
    if unsummarized > 0 {
        let detail = format!("{unsummarized} more refused over {windows} earlier hour(s)");
        audit(
            tx,
            Event::WorkerEnrollmentRefused,
            None,
            None,
            false,
            Some(&detail),
        )?;
        tx.prepare_cached(
            "UPDATE worker_enrollment_refusals SET summarized = 1
             WHERE window_ms < ?1 AND suppressed > 0 AND summarized = 0",
        )?
        .execute([window])?;
    }
    tx.prepare_cached("DELETE FROM worker_enrollment_refusals WHERE window_ms < ?1")?
        .execute([window - REFUSAL_KEEP_MS])?;

    let own: Option<i64> = tx
        .prepare_cached(
            "SELECT recorded FROM worker_enrollment_refusals WHERE window_ms = ?1 AND peer = ?2",
        )?
        .query_row(params![window, peer], |r| r.get(0))
        .optional()?;
    let (peer, own) = match own {
        Some(own) => (peer, own),
        None => {
            let tracked: i64 = tx
                .prepare_cached(
                    "SELECT COUNT(*) FROM worker_enrollment_refusals WHERE window_ms = ?1",
                )?
                .query_row([window], |r| r.get(0))?;
            if tracked < REFUSAL_PEERS_PER_WINDOW {
                (peer, 0)
            } else {
                let shared: Option<i64> = tx
                    .prepare_cached(
                        "SELECT recorded FROM worker_enrollment_refusals
                         WHERE window_ms = ?1 AND peer = ?2",
                    )?
                    .query_row(params![window, UNATTRIBUTED], |r| r.get(0))
                    .optional()?;
                (UNATTRIBUTED, shared.unwrap_or(0))
            }
        }
    };
    let total: i64 = tx
        .prepare_cached(
            "SELECT COALESCE(SUM(recorded), 0) FROM worker_enrollment_refusals WHERE window_ms = ?1",
        )?
        .query_row([window], |r| r.get(0))?;
    let written = own < REFUSAL_ROWS_PER_PEER && total < REFUSAL_ROWS_PER_WINDOW;
    tx.prepare_cached(
        "INSERT INTO worker_enrollment_refusals(window_ms, peer, recorded, suppressed)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(window_ms, peer) DO UPDATE SET
             recorded = recorded + excluded.recorded, suppressed = suppressed + excluded.suppressed",
    )?
    .execute(params![window, peer, i64::from(written), i64::from(!written)])?;
    if written {
        audit(tx, Event::WorkerEnrollmentRefused, None, None, false, None)?;
    }
    Ok(())
}

/// Refusals over the kept windows: `(with an audit row, counted only)`.
pub fn refusal_counts(conn: &Connection) -> Result<(i64, i64)> {
    Ok(conn.query_row(
        "SELECT COALESCE(SUM(recorded), 0), COALESCE(SUM(suppressed), 0)
         FROM worker_enrollment_refusals",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?)
}

/// Redeem an enrollment for a machine that states its own identity over HTTPS (Q11): the secret
/// authorizes the TLS fingerprint and, for a Tailcat enrollment, the node key the machine presents,
/// and both are bound to the pool in the one transaction that spends the enrollment. The machine has
/// no tunnel yet, so nothing else can vouch for its key.
///
/// - An enrollment an administrator already authorized a key for (`authorize_node_key`) is redeemed
///   only by that exact worker identifier and key.
/// - A key reserved for a different pending enrollment is `Conflict`, like one already bound.
/// - A spent secret presented again within `REPLAY_WINDOW_MS` by the same worker identifier, TLS
///   fingerprint and node key is answered with the worker it already created and changes nothing; any
///   other presentation of it is refused as a value.
///
/// Refusal is `Ok(None)` and leaves the enrollment unspent; the audit row it writes is bounded.
pub fn redeem_presented(
    tx: &Transaction<'_>,
    presented: &Secret,
    presentation: Presentation<'_>,
    node_key: Option<NodeKey>,
    now: UnixMillis,
) -> Result<Option<Worker>> {
    redeem_presented_from(tx, presented, presentation, node_key, now, UNATTRIBUTED)
}

/// `redeem_presented` with the refusal charged to `peer` (see `record_refusal`).
pub fn redeem_presented_from(
    tx: &Transaction<'_>,
    presented: &Secret,
    presentation: Presentation<'_>,
    node_key: Option<NodeKey>,
    now: UnixMillis,
    peer: Peer,
) -> Result<Option<Worker>> {
    let digest = presented.digest();
    let known: Option<(AuthorizedPair, Option<i64>)> = tx
        .prepare_cached(
            "SELECT authorized_worker, authorized_node_key, redeemed_ms FROM worker_enrollments
             WHERE token_digest = ?1 AND revoked_ms IS NULL",
        )?
        .query_row([digest.0], |r| Ok(((r.get(0)?, r.get(1)?), r.get(2)?)))
        .optional()?;
    match known {
        Some((_, Some(redeemed))) => {
            return replay(
                tx,
                presentation,
                node_key,
                now.0.saturating_sub(redeemed) <= REPLAY_WINDOW_MS,
                (peer, now),
            );
        }
        Some(((Some(worker), Some(key)), None))
            if worker.as_slice() != presentation.worker.as_bytes()
                || Some(key.as_slice()) != node_key.as_ref().map(<[u8; 32]>::as_slice) =>
        {
            record_refusal(tx, peer, now)?;
            return Ok(None);
        }
        _ => {}
    }
    if let Some(key) = &node_key {
        let reserved: bool = tx
            .prepare_cached(
                "SELECT EXISTS(SELECT 1 FROM worker_enrollments
                 WHERE authorized_node_key = ?1 AND redeemed_ms IS NULL AND revoked_ms IS NULL
                   AND token_digest != ?2)",
            )?
            .query_row(params![key.as_slice(), digest.0], |r| r.get(0))?;
        if reserved {
            return Err(Error::Conflict);
        }
    }
    redeem_bound_from(tx, presented, presentation, node_key, now, peer)
}

/// The answer to a spent secret presented again by the machine it created (see `redeem_presented`).
fn replay(
    tx: &Transaction<'_>,
    presentation: Presentation<'_>,
    node_key: Option<NodeKey>,
    within_window: bool,
    (peer, now): (Peer, UnixMillis),
) -> Result<Option<Worker>> {
    if within_window
        && let Ok(worker) = authenticate(tx, &presentation.fingerprint)
        && worker.id == presentation.worker
        && worker.node_key == node_key
        && worker.uninstall_requested.is_none()
    {
        return Ok(Some(worker));
    }
    record_refusal(tx, peer, now)?;
    Ok(None)
}

/// State a pending Tailcat enrollment needs before its worker can reach the controller: which
/// worker identifier and which node key it is for. The pair is set once by platform
/// administration, and redemption binds exactly that key to exactly that identifier. Until the
/// enrollment is spent, withdrawn or expired the controller admits the key to its Tailcat helper
/// (`pending_node_keys`), so the worker can present the enrollment secret at all; afterwards the
/// worker's own `node_key` takes over (`admitted_node_keys`).
///
/// Idempotent for the same pair. A direct-TLS enrollment takes no key (`InvalidInput`); a spent,
/// withdrawn or expired one, a second pair, and a key or identifier that already belongs to a
/// worker are `Conflict`.
pub fn authorize_node_key(
    tx: &Transaction<'_>,
    authority: Authority,
    enrollment: TokenId,
    worker: WorkerId,
    key: NodeKey,
    now: UnixMillis,
) -> Result<()> {
    authority.require_platform(tx)?;
    let status = enrollment_status_of(tx, enrollment, now)?;
    if status.state != EnrollmentState::Pending {
        return Err(Error::Conflict);
    }
    if !status.tailcat {
        return Err(Error::InvalidInput("node key for a direct enrollment"));
    }
    let current: AuthorizedPair = tx
        .prepare_cached(
            "SELECT authorized_worker, authorized_node_key FROM worker_enrollments WHERE id = ?1",
        )?
        .query_row([enrollment.as_bytes()], |r| Ok((r.get(0)?, r.get(1)?)))?;
    if let (Some(w), Some(k)) = &current {
        return if w.as_slice() == worker.as_bytes() && k.as_slice() == key {
            Ok(())
        } else {
            Err(Error::Conflict)
        };
    }
    let taken: bool = tx
        .prepare_cached("SELECT EXISTS(SELECT 1 FROM workers WHERE id = ?1 OR node_key = ?2)")?
        .query_row(params![worker.as_bytes(), key.as_slice()], |r| r.get(0))?;
    if taken {
        return Err(Error::Conflict);
    }
    let set = tx.execute(
        "UPDATE worker_enrollments SET authorized_worker = ?2, authorized_node_key = ?3
         WHERE id = ?1 AND redeemed_ms IS NULL AND revoked_ms IS NULL",
        params![enrollment.as_bytes(), worker.as_bytes(), key.as_slice()],
    );
    // Another pending enrollment already holds this key.
    if let Err(rusqlite::Error::SqliteFailure(code, _)) = &set
        && code.code == rusqlite::ErrorCode::ConstraintViolation
    {
        return Err(Error::Conflict);
    }
    set?;
    audit(
        tx,
        Event::WorkerNodeKeyAuthorized,
        authority.actor(),
        None,
        authority.host_local(),
        Some(&enrollment.to_string()),
    )
}

/// The node keys of enrollments that can still be redeemed, for the Tailcat allow list: without
/// them a new worker could never reach the controller to present its secret. A key leaves this
/// list the moment its enrollment is spent (then `admitted_node_keys` carries it), withdrawn or
/// expired, or its pool is deactivated.
pub fn pending_node_keys(conn: &Connection, now: UnixMillis) -> Result<Vec<(WorkerId, NodeKey)>> {
    let mut stmt = conn.prepare_cached(
        "SELECT e.authorized_worker, e.authorized_node_key
         FROM worker_enrollments e JOIN pools p ON p.id = e.pool_id
         WHERE e.authorized_node_key IS NOT NULL AND e.redeemed_ms IS NULL
           AND e.revoked_ms IS NULL AND e.expires_ms > ?1 AND p.active = 1
         ORDER BY e.created_ms, e.id",
    )?;
    let rows = stmt.query_map([now.0], |r| {
        Ok((r.get::<_, [u8; 16]>(0)?, r.get::<_, Vec<u8>>(1)?))
    })?;
    rows.map(|row| {
        let (id, key) = row?;
        Ok((
            WorkerId::from_bytes(id).map_err(|_| Error::Corrupt("worker id"))?,
            NodeKey::try_from(key).map_err(|_| Error::Corrupt("enrollment node key"))?,
        ))
    })
    .collect()
}

/// Redeem an enrollment the way the controller's link does: a Tailcat enrollment binds the node
/// key an administrator authorized for it, and only for the worker identifier it was authorized
/// for; a direct-TLS enrollment binds none. A Tailcat enrollment with no authorized key, or one
/// presented by a different identifier, is refused as a value and stays unspent.
pub fn redeem_authorized(
    tx: &Transaction<'_>,
    presented: &Secret,
    presentation: Presentation<'_>,
    now: UnixMillis,
) -> Result<Option<Worker>> {
    redeem_authorized_from(tx, presented, presentation, now, UNATTRIBUTED)
}

/// `redeem_authorized` with the refusal charged to `peer` (see `record_refusal`).
pub fn redeem_authorized_from(
    tx: &Transaction<'_>,
    presented: &Secret,
    presentation: Presentation<'_>,
    now: UnixMillis,
    peer: Peer,
) -> Result<Option<Worker>> {
    let authorized: Option<AuthorizedPair> = tx
        .prepare_cached(
            "SELECT authorized_worker, authorized_node_key FROM worker_enrollments
             WHERE token_digest = ?1",
        )?
        .query_row([presented.digest().0], |r| Ok((r.get(0)?, r.get(1)?)))
        .optional()?;
    let node_key = match authorized {
        Some((Some(worker), Some(key))) if worker.as_slice() == presentation.worker.as_bytes() => {
            NodeKey::try_from(key).ok()
        }
        _ => None,
    };
    redeem_bound_from(tx, presented, presentation, node_key, now, peer)
}

type PoolBytes = [u8; 16];
/// The worker identifier and node key an administrator authorized for an enrollment, as stored.
type AuthorizedPair = (Option<Vec<u8>>, Option<Vec<u8>>);

// Negotiation runs on every hello; dropping below the profile protocol clears the placement facts (labels, images, disk) that an old worker cannot report, so stale ones never match.
pub fn renegotiate(tx: &Transaction<'_>, worker: WorkerId, negotiated: Negotiated) -> Result<()> {
    let profiled = negotiated.protocol.0 >= sentinel_protocol::negotiate::PROFILE_MIN.0;
    let changed = tx
        .prepare_cached(
            "UPDATE workers SET protocol = ?2, capabilities = ?3,
                    labels = CASE WHEN ?5 THEN labels ELSE X'' END,
                    avail_images = CASE WHEN ?5 THEN avail_images ELSE X'' END,
                    disk_bytes = CASE WHEN ?5 THEN disk_bytes ELSE 0 END
             WHERE id = ?1 AND revoked_ms IS NULL AND arch = ?4",
        )?
        .execute(params![
            worker.as_bytes(),
            i64::from(negotiated.protocol.0),
            negotiated.capabilities.0 as i64,
            arch_name(negotiated.arch),
            profiled
        ])?;
    if changed == 0 {
        let known: bool = tx
            .prepare_cached(
                "SELECT EXISTS(SELECT 1 FROM workers WHERE id = ?1 AND revoked_ms IS NULL)",
            )?
            .query_row([worker.as_bytes()], |r| r.get(0))?;
        return Err(if known {
            Error::Conflict
        } else {
            Error::NotFound
        });
    }
    Ok(())
}

pub fn software_label(announced: &str) -> Option<String> {
    let label: String = announced
        .chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .take(128)
        .collect();
    let label = label.trim();
    (!label.is_empty()).then(|| label.to_owned())
}

pub fn record_software(tx: &Transaction<'_>, worker: WorkerId, software: &str) -> Result<()> {
    tx.prepare_cached("UPDATE workers SET software = ?2 WHERE id = ?1")?
        .execute(params![worker.as_bytes(), software])?;
    Ok(())
}

const WORKER_COLUMNS: &str = "w.id, w.pool_id, w.fingerprint, w.name, w.arch, w.capabilities,
    w.protocol, w.enrolled_ms, w.last_seen_ms, w.software, w.cpu_ceiling_millis,
    w.memory_ceiling_bytes, w.disk_ceiling_bytes, w.priority, w.node_key, w.uninstall_ms";

// Column values as stored; `into_worker` validates them so a corrupt row is `Corrupt`, not "unknown".
struct RawWorker {
    id: [u8; 16],
    pool: [u8; 16],
    fingerprint: [u8; 32],
    name: String,
    arch: String,
    capabilities: i64,
    protocol: i64,
    enrolled: i64,
    last_seen: Option<i64>,
    software: Option<String>,
    policy: HostPolicy,
    node_key: Option<Vec<u8>>,
    uninstall: Option<i64>,
}

impl RawWorker {
    fn read(r: &rusqlite::Row<'_>) -> rusqlite::Result<RawWorker> {
        Ok(RawWorker {
            id: r.get(0)?,
            pool: r.get(1)?,
            fingerprint: r.get(2)?,
            name: r.get(3)?,
            arch: r.get(4)?,
            capabilities: r.get(5)?,
            protocol: r.get(6)?,
            enrolled: r.get(7)?,
            last_seen: r.get(8)?,
            software: r.get(9)?,
            policy: HostPolicy {
                cpu_millis: r.get(10)?,
                memory_bytes: r.get(11)?,
                disk_bytes: r.get(12)?,
                priority: r.get(13)?,
            },
            node_key: r.get(14)?,
            uninstall: r.get(15)?,
        })
    }

    fn into_worker(self) -> Result<Worker> {
        Ok(Worker {
            id: WorkerId::from_bytes(self.id).map_err(|_| Error::Corrupt("worker id"))?,
            pool: PoolId::from_bytes(self.pool).map_err(|_| Error::Corrupt("pool id"))?,
            fingerprint: Digest(self.fingerprint),
            name: self.name,
            negotiated: Negotiated {
                protocol: ProtocolVersion(
                    u16::try_from(self.protocol).map_err(|_| Error::Corrupt("workers.protocol"))?,
                ),
                capabilities: Capabilities(
                    u64::try_from(self.capabilities)
                        .map_err(|_| Error::Corrupt("workers.capabilities"))?,
                ),
                arch: parse_arch(&self.arch).ok_or(Error::Corrupt("workers.arch"))?,
            },
            enrolled: UnixMillis(self.enrolled),
            last_seen: self.last_seen.map(UnixMillis),
            software: self.software,
            policy: self.policy,
            node_key: self
                .node_key
                .map(|bytes| {
                    NodeKey::try_from(bytes).map_err(|_| Error::Corrupt("workers.node_key"))
                })
                .transpose()?,
            uninstall_requested: self.uninstall.map(UnixMillis),
        })
    }
}

pub fn authenticate(conn: &Connection, fingerprint: &Digest) -> Result<Worker> {
    conn.prepare_cached(&format!(
        "SELECT {WORKER_COLUMNS}
         FROM workers w JOIN pools p ON p.id = w.pool_id
         WHERE w.fingerprint = ?1 AND w.revoked_ms IS NULL AND p.active = 1"
    ))?
    .query_row([fingerprint.0], RawWorker::read)
    .optional()?
    .ok_or(Error::NotFound)?
    .into_worker()
}

/// The worker whose TLS fingerprint **and** Tailcat node key were bound by one enrollment. A
/// fingerprint of one worker with the node key of another, or a worker enrolled without a node
/// key, is `NotFound` like any unknown identity.
pub fn authenticate_bound(
    conn: &Connection,
    fingerprint: &Digest,
    node_key: &NodeKey,
) -> Result<Worker> {
    let worker = authenticate(conn, fingerprint)?;
    if worker.node_key.as_ref() == Some(node_key) {
        Ok(worker)
    } else {
        Err(Error::NotFound)
    }
}

/// The node keys the controller admits: every live worker's bound key, for the Tailcat allow list.
pub fn admitted_node_keys(conn: &Connection) -> Result<Vec<(WorkerId, NodeKey)>> {
    let mut stmt = conn.prepare_cached(
        "SELECT w.id, w.node_key FROM workers w JOIN pools p ON p.id = w.pool_id
         WHERE w.node_key IS NOT NULL AND w.revoked_ms IS NULL AND p.active = 1
         ORDER BY w.enrolled_ms, w.id",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok((r.get::<_, [u8; 16]>(0)?, r.get::<_, Vec<u8>>(1)?))
    })?;
    rows.map(|row| {
        let (id, key) = row?;
        Ok((
            WorkerId::from_bytes(id).map_err(|_| Error::Corrupt("worker id"))?,
            NodeKey::try_from(key).map_err(|_| Error::Corrupt("workers.node_key"))?,
        ))
    })
    .collect()
}

/// Replace a live worker's approved ceilings and priority (platform administration only). The
/// effective size the controller offers is recomputed from what the worker last reported, under the
/// new ceilings, in both directions: a reduction stops new oversubscription at once, and a raise or
/// removal takes effect at once as well, up to the host's own report and never beyond it. Attempts
/// the worker already holds are untouched; a reduction only drives the free room negative. A size
/// the worker has not reported yet (0) is only ever reduced, never raised. Audited.
pub fn set_policy(
    tx: &Transaction<'_>,
    authority: Authority,
    worker: WorkerId,
    policy: HostPolicy,
) -> Result<()> {
    authority.require_platform(tx)?;
    policy.validate()?;
    let changed = tx.execute(
        "UPDATE workers SET cpu_ceiling_millis = ?2, memory_ceiling_bytes = ?3,
                disk_ceiling_bytes = ?4, priority = ?5,
                cpu_millis = CASE
                    WHEN reported_cpu_millis > 0 THEN MIN(reported_cpu_millis, COALESCE(?2, reported_cpu_millis))
                    WHEN ?2 IS NOT NULL AND cpu_millis > ?2 THEN ?2
                    ELSE cpu_millis END,
                memory_bytes = CASE
                    WHEN reported_memory_bytes > 0 THEN MIN(reported_memory_bytes, COALESCE(?3, reported_memory_bytes))
                    WHEN ?3 IS NOT NULL AND memory_bytes > ?3 THEN ?3
                    ELSE memory_bytes END,
                disk_bytes = CASE
                    WHEN reported_disk_bytes > 0 THEN MIN(reported_disk_bytes, COALESCE(?4, reported_disk_bytes))
                    WHEN ?4 IS NOT NULL THEN ?4
                    ELSE 0 END
         WHERE id = ?1 AND revoked_ms IS NULL",
        params![
            worker.as_bytes(),
            policy.cpu_millis,
            policy.memory_bytes,
            policy.disk_bytes,
            policy.priority
        ],
    )?;
    if changed == 0 {
        return Err(Error::NotFound);
    }
    let detail = format!(
        "{worker} cpu={} memory={} disk={} priority={}",
        ceiling(policy.cpu_millis),
        ceiling(policy.memory_bytes),
        ceiling(policy.disk_bytes),
        policy.priority
    );
    audit(
        tx,
        Event::WorkerPolicyChanged,
        authority.actor(),
        None,
        authority.host_local(),
        Some(&detail),
    )
}

fn ceiling(value: Option<i64>) -> String {
    value.map_or_else(|| "none".to_owned(), |v| v.to_string())
}

/// A live worker as the controller sees its host: what the controller approved, what the worker
/// reported about itself and what the controller therefore offers. `reported_*` is 0 until the
/// worker states that size.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostView {
    pub policy: HostPolicy,
    pub reported_cpu_millis: i64,
    pub reported_memory_bytes: i64,
    pub reported_disk_bytes: i64,
    pub effective_cpu_millis: i64,
    pub effective_memory_bytes: i64,
    pub effective_disk_bytes: i64,
    /// What the unreleased attempts of the worker's whole machine reserve right now.
    pub reserved_cpu_millis: i64,
    pub reserved_memory_bytes: i64,
    pub reserved_disk_bytes: i64,
}

/// How far the work a machine already accepted exceeds what the controller now offers it. All zero
/// means within the cap. A ceiling lowered under running work leaves this positive until that work
/// settles: nothing new is placed on the machine meanwhile, and nothing accepted is stopped.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OverCap {
    pub cpu_millis: i64,
    pub memory_bytes: i64,
    pub disk_bytes: i64,
}

impl OverCap {
    pub fn is_over(&self) -> bool {
        self.cpu_millis > 0 || self.memory_bytes > 0 || self.disk_bytes > 0
    }
}

impl HostView {
    /// The amount by which the reservations exceed the effective size, per resource. A size the
    /// controller does not enforce (0: a worker that has not stated it, or a disk nobody measured)
    /// is never over.
    pub fn over_cap(&self) -> OverCap {
        let over = |reserved: i64, effective: i64| {
            if effective > 0 {
                (reserved - effective).max(0)
            } else {
                0
            }
        };
        OverCap {
            cpu_millis: over(self.reserved_cpu_millis, self.effective_cpu_millis),
            memory_bytes: over(self.reserved_memory_bytes, self.effective_memory_bytes),
            disk_bytes: over(self.reserved_disk_bytes, self.effective_disk_bytes),
        }
    }
}

/// The policy, report and effective size of one live worker (platform administration only).
pub fn host_view(conn: &Connection, authority: Authority, worker: WorkerId) -> Result<HostView> {
    authority.require_platform(conn)?;
    let reserved = crate::dispatch::reserved_on_host(conn, worker)?;
    conn.prepare_cached(
        "SELECT cpu_ceiling_millis, memory_ceiling_bytes, disk_ceiling_bytes, priority,
                reported_cpu_millis, reported_memory_bytes, reported_disk_bytes,
                cpu_millis, memory_bytes, disk_bytes
         FROM workers WHERE id = ?1 AND revoked_ms IS NULL",
    )?
    .query_row([worker.as_bytes()], |r| {
        Ok(HostView {
            reserved_cpu_millis: reserved.cpu_millis,
            reserved_memory_bytes: reserved.memory_bytes,
            reserved_disk_bytes: reserved.disk_bytes,
            policy: HostPolicy {
                cpu_millis: r.get(0)?,
                memory_bytes: r.get(1)?,
                disk_bytes: r.get(2)?,
                priority: r.get(3)?,
            },
            reported_cpu_millis: r.get(4)?,
            reported_memory_bytes: r.get(5)?,
            reported_disk_bytes: r.get(6)?,
            effective_cpu_millis: r.get(7)?,
            effective_memory_bytes: r.get(8)?,
            effective_disk_bytes: r.get(9)?,
        })
    })
    .optional()?
    .ok_or(Error::NotFound)
}

/// Ask for a worker to be uninstalled: no new work is placed on it from now on (it drains), and
/// `settle_uninstalls` revokes it, with its TLS fingerprint and node key, once the work it already
/// accepted has settled. Idempotent; the first request's time stands.
pub fn request_uninstall(
    tx: &Transaction<'_>,
    authority: Authority,
    worker: WorkerId,
    now: UnixMillis,
) -> Result<()> {
    authority.require_platform(tx)?;
    let changed = tx.execute(
        "UPDATE workers SET uninstall_ms = COALESCE(uninstall_ms, ?2),
                drain_ms = COALESCE(drain_ms, ?2)
         WHERE id = ?1 AND revoked_ms IS NULL",
        params![worker.as_bytes(), now.0],
    )?;
    if changed == 0 {
        return Err(Error::NotFound);
    }
    audit(
        tx,
        Event::WorkerUninstallRequested,
        authority.actor(),
        None,
        authority.host_local(),
        None,
    )
}

/// Whether any uninstall is waiting for its work to settle: one indexed probe, so the controller's
/// pass can skip the write when there is nothing to do.
pub fn uninstalling(conn: &Connection) -> Result<bool> {
    Ok(conn
        .prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM workers
                           WHERE uninstall_ms IS NOT NULL AND revoked_ms IS NULL)",
        )?
        .query_row([], |r| r.get(0))?)
}

/// Revoke every worker whose uninstall was requested and which holds no unreleased attempt.
pub fn settle_uninstalls(tx: &Transaction<'_>, now: UnixMillis) -> Result<Vec<WorkerId>> {
    let ready: Vec<WorkerId> = {
        let mut stmt = tx.prepare_cached(
            "SELECT w.id FROM workers w
             WHERE w.uninstall_ms IS NOT NULL AND w.revoked_ms IS NULL
               AND NOT EXISTS(SELECT 1 FROM attempts a
                              WHERE a.worker_id = w.id AND a.released_ms IS NULL)",
        )?;
        stmt.query_map([], |r| r.get::<_, [u8; 16]>(0))?
            .map(|row| WorkerId::from_bytes(row?).map_err(|_| Error::Corrupt("worker id")))
            .collect::<Result<_>>()?
    };
    for worker in &ready {
        tx.execute(
            "UPDATE workers SET revoked_ms = ?2 WHERE id = ?1 AND revoked_ms IS NULL",
            params![worker.as_bytes(), now.0],
        )?;
        audit(tx, Event::WorkerUninstalled, None, None, false, None)?;
    }
    Ok(ready)
}

pub fn seen_due(worker: &Worker, now: UnixMillis) -> bool {
    worker
        .last_seen
        .is_none_or(|last| now.0.saturating_sub(last.0) >= SEEN_RECORD_INTERVAL_MS)
}

pub fn seen(tx: &Transaction<'_>, worker: WorkerId, now: UnixMillis) -> Result<()> {
    tx.execute(
        "UPDATE workers SET last_seen_ms = ?2 WHERE id = ?1 AND revoked_ms IS NULL
         AND (last_seen_ms IS NULL OR last_seen_ms < ?2)",
        params![worker.as_bytes(), now.0],
    )?;
    Ok(())
}

pub fn revoke(
    tx: &Transaction<'_>,
    authority: Authority,
    worker: WorkerId,
    now: UnixMillis,
) -> Result<()> {
    authority.require_platform(tx)?;
    let changed = tx.execute(
        "UPDATE workers SET revoked_ms = ?2 WHERE id = ?1 AND revoked_ms IS NULL",
        params![worker.as_bytes(), now.0],
    )?;
    if changed == 0 {
        return Err(Error::NotFound);
    }
    audit(
        tx,
        Event::WorkerRevoked,
        authority.actor(),
        None,
        authority.host_local(),
        None,
    )
}

pub fn drain(
    tx: &Transaction<'_>,
    authority: Authority,
    worker: WorkerId,
    now: UnixMillis,
) -> Result<()> {
    authority.require_platform(tx)?;
    let changed = tx.execute(
        "UPDATE workers SET drain_ms = COALESCE(drain_ms, ?2)
         WHERE id = ?1 AND revoked_ms IS NULL",
        params![worker.as_bytes(), now.0],
    )?;
    if changed == 0 {
        return Err(Error::NotFound);
    }
    Ok(())
}

pub fn undrain(tx: &Transaction<'_>, authority: Authority, worker: WorkerId) -> Result<()> {
    authority.require_platform(tx)?;
    let changed = tx.execute(
        "UPDATE workers SET drain_ms = NULL WHERE id = ?1 AND revoked_ms IS NULL AND drain_ms IS NOT NULL",
        [worker.as_bytes()],
    )?;
    let known: bool = tx
        .prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM workers WHERE id = ?1 AND revoked_ms IS NULL)",
        )?
        .query_row([worker.as_bytes()], |r| r.get(0))?;
    if changed == 0 && !known {
        return Err(Error::NotFound);
    }
    Ok(())
}

pub fn in_pool(conn: &Connection, authority: Authority, pool: PoolId) -> Result<Vec<Worker>> {
    if authority.require_platform(conn).is_err() {
        let principal = authority.principal().ok_or(Error::NotFound)?;
        let admitted: bool = conn
            .prepare_cached(
                "SELECT EXISTS(
                    SELECT 1 FROM pools p JOIN memberships m ON m.user_id = ?2
                    JOIN tenants t ON t.id = m.tenant_id AND t.active = 1
                    LEFT JOIN pool_grants g ON g.pool_id = p.id AND g.tenant_id = t.id
                    WHERE p.id = ?1 AND (p.owner_tenant_id = t.id OR g.tenant_id IS NOT NULL))",
            )?
            .query_row(params![pool.as_bytes(), principal.user.as_bytes()], |r| {
                r.get(0)
            })?;
        if !admitted {
            return Err(Error::NotFound);
        }
    }
    let mut stmt = conn.prepare_cached(&format!(
        "SELECT {WORKER_COLUMNS} FROM workers w
         WHERE w.pool_id = ?1 AND w.revoked_ms IS NULL ORDER BY w.enrolled_ms, w.id"
    ))?;
    let rows = stmt.query_map([pool.as_bytes()], RawWorker::read)?;
    rows.map(|row| row?.into_worker()).collect()
}

/// Every live worker with its host policy view, oldest first, optionally for one pool (platform
/// administration only). A worker whose uninstall was requested stays listed, marked, until it settles.
pub fn hosts(
    conn: &Connection,
    authority: Authority,
    pool: Option<PoolId>,
) -> Result<Vec<(Worker, HostView)>> {
    authority.require_platform(conn)?;
    let mut stmt = conn.prepare_cached(&format!(
        "SELECT {WORKER_COLUMNS} FROM workers w
         WHERE w.revoked_ms IS NULL AND (?1 IS NULL OR w.pool_id = ?1)
         ORDER BY w.enrolled_ms, w.id"
    ))?;
    let rows = stmt.query_map(
        params![pool.map(|p| p.as_bytes().to_vec())],
        RawWorker::read,
    )?;
    let workers = rows
        .map(|row| row?.into_worker())
        .collect::<Result<Vec<_>>>()?;
    // The listing and each view are separate reads, so a worker revoked between them is no longer live: leave it out
    // rather than failing the whole listing.
    let mut live = Vec::with_capacity(workers.len());
    for worker in workers {
        match host_view(conn, authority, worker.id) {
            Ok(view) => live.push((worker, view)),
            Err(Error::NotFound) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(live)
}

const fn arch_name(arch: Arch) -> &'static str {
    match arch {
        Arch::X86_64 => "x86_64",
        Arch::Aarch64 => "aarch64",
    }
}

fn parse_arch(text: &str) -> Option<Arch> {
    match text {
        "x86_64" => Some(Arch::X86_64),
        "aarch64" => Some(Arch::Aarch64),
        _ => None,
    }
}

pub fn revoked(conn: &Connection, worker: WorkerId) -> Result<bool> {
    Ok(conn
        .prepare_cached("SELECT revoked_ms IS NOT NULL FROM workers WHERE id = ?1")?
        .query_row([worker.as_bytes()], |row| row.get::<_, bool>(0))
        .optional()?
        .unwrap_or(false))
}

/// Whether a TLS fingerprint belongs to a worker that was revoked or uninstalled. A revoked identity
/// never authenticates again; this lets the controller say so instead of "not enrolled".
pub fn revoked_fingerprint(conn: &Connection, fingerprint: &Digest) -> Result<bool> {
    Ok(conn
        .prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM workers WHERE fingerprint = ?1 AND revoked_ms IS NOT NULL)",
        )?
        .query_row([fingerprint.0], |row| row.get::<_, bool>(0))?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn view(reserved: (i64, i64, i64), effective: (i64, i64, i64)) -> HostView {
        HostView {
            policy: HostPolicy::default(),
            reported_cpu_millis: 8_000,
            reported_memory_bytes: 8,
            reported_disk_bytes: 8,
            effective_cpu_millis: effective.0,
            effective_memory_bytes: effective.1,
            effective_disk_bytes: effective.2,
            reserved_cpu_millis: reserved.0,
            reserved_memory_bytes: reserved.1,
            reserved_disk_bytes: reserved.2,
        }
    }

    #[test]
    fn over_cap_is_the_reservation_beyond_the_offered_size_per_resource() {
        let within = view((1_000, 4, 10), (2_000, 4, 10));
        assert!(
            !within.over_cap().is_over(),
            "exactly at the cap is within it"
        );
        let over = view((2_500, 9, 10), (1_000, 4, 10)).over_cap();
        assert_eq!(
            (over.cpu_millis, over.memory_bytes, over.disk_bytes),
            (1_500, 5, 0)
        );
        assert!(over.is_over());
    }

    #[test]
    fn a_size_nobody_stated_is_never_over() {
        // A worker that has not reported (0) or a disk nobody measured (0) is not enforced, so held
        // work cannot be over it.
        let over = view((1_000, 4, 10), (0, 0, 0)).over_cap();
        assert!(!over.is_over());
    }
}
