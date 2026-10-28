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
    Ok(())
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

// Refusal is Ok(None), not Err: an Err would roll back the audit row a committing caller must keep.
pub fn redeem(
    tx: &Transaction<'_>,
    presented: &Secret,
    presentation: Presentation<'_>,
    now: UnixMillis,
) -> Result<Option<Worker>> {
    redeem_bound(tx, presented, presentation, None, now)
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
        audit(tx, Event::WorkerEnrollmentRefused, None, None, false, None)?;
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

type PoolBytes = [u8; 16];

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

/// Replace a live worker's approved ceilings and priority (platform administration only). A
/// reduction clamps the recorded capacity at once, so no new work is placed over it; attempts the
/// worker already holds are untouched. A raise or removal takes effect at the worker's next
/// capacity report, which is the only place the host's own size is learned.
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
                cpu_millis = CASE WHEN ?2 IS NOT NULL AND cpu_millis > ?2 THEN ?2 ELSE cpu_millis END,
                memory_bytes = CASE WHEN ?3 IS NOT NULL AND memory_bytes > ?3 THEN ?3
                                    ELSE memory_bytes END,
                disk_bytes = CASE WHEN ?4 IS NULL THEN disk_bytes
                                  WHEN disk_bytes = 0 OR disk_bytes > ?4 THEN ?4
                                  ELSE disk_bytes END
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
    Ok(())
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
