//! Worker enrollment, identity and liveness (W01).
//!
//! A worker is admitted the way a person is: by a one-time, expiring secret an
//! operator hands to the machine, redeemed exactly once. What the redemption
//! binds is an identity the *worker* generated — the fingerprint of its own
//! TLS certificate — to the *pool the operator chose*. From then on the
//! controller knows the worker by that fingerprint alone; no private material
//! is ever stored, and the worker cannot choose or change its pool.
//!
//! Sessions are authenticated by presenting that certificate over TLS
//! (`sentinel-link`); this module answers whether the fingerprint is a live,
//! unrevoked worker of an active pool, and records that it was seen.

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
/// Enrollment is a bootstrap step, not a standing right: an hour by default.
pub const DEFAULT_ENROLLMENT_MS: i64 = 60 * 60 * 1000;
pub const MAX_ENROLLMENT_MS: i64 = DAY_MS;
/// Liveness is recorded at most this often per worker, so a heartbeat every
/// few seconds costs the writer one row update per minute, not per beat.
pub const SEEN_RECORD_INTERVAL_MS: i64 = 60 * 1000;

/// A worker's stored identity: everything the controller knows about it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Worker {
    pub id: WorkerId,
    pub pool: PoolId,
    pub fingerprint: Digest,
    pub name: String,
    pub negotiated: Negotiated,
    pub enrolled: UnixMillis,
    pub last_seen: Option<UnixMillis>,
}

/// The enrollment secret, shown once. Delivered to the machine out of band.
pub struct Enrollment {
    pub id: TokenId,
    pub secret: Secret,
    pub pool: PoolId,
    pub expires: UnixMillis,
}

/// Issue an enrollment for one pool. Platform administration: pools are the
/// platform's capacity, and admitting a machine to one is a platform decision.
pub fn issue_enrollment(
    tx: &Transaction<'_>,
    authority: Authority,
    pool: PoolId,
    lifetime_ms: i64,
    now: UnixMillis,
) -> Result<Enrollment> {
    authority.require_platform(tx)?;
    if !(1..=MAX_ENROLLMENT_MS).contains(&lifetime_ms) {
        return Err(Error::InvalidInput("enrollment lifetime"));
    }
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
        "INSERT INTO worker_enrollments(token_digest, id, pool_id, created_by, created_ms, expires_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            secret.digest().0,
            id.as_bytes(),
            pool.as_bytes(),
            authority.actor().as_ref().map(UserId::as_bytes),
            now.0,
            expires.0
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
    })
}

/// Withdraw an unspent enrollment.
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

/// What a worker says about itself at enrollment. Everything here is bounded;
/// the negotiated set is what the controller accepted, not what was claimed.
#[derive(Clone, Debug)]
pub struct Presentation<'a> {
    pub worker: WorkerId,
    pub fingerprint: Digest,
    pub name: &'a str,
    pub negotiated: Negotiated,
}

/// Redeem an enrollment: single use, before expiry, binding the presented
/// identity to the enrollment's pool. The worker chose its identifier and its
/// key; the operator chose the pool; nothing else is negotiable here.
pub fn enroll(
    tx: &Transaction<'_>,
    presented: &Secret,
    presentation: Presentation<'_>,
    now: UnixMillis,
) -> Result<Worker> {
    if presentation.name.is_empty()
        || presentation.name.len() > 128
        || presentation.name.chars().any(char::is_control)
    {
        return Err(Error::InvalidInput("worker name"));
    }
    let digest = presented.digest();
    let pool: Option<[u8; 16]> = tx
        .prepare_cached(
            "SELECT e.pool_id FROM worker_enrollments e JOIN pools p ON p.id = e.pool_id
             WHERE e.token_digest = ?1 AND e.redeemed_ms IS NULL AND e.revoked_ms IS NULL
             AND e.expires_ms > ?2 AND p.active = 1",
        )?
        .query_row(params![digest.0, now.0], |r| r.get(0))
        .optional()?;
    let Some(pool) = pool else {
        audit(tx, Event::WorkerEnrollmentRefused, None, None, false, None)?;
        return Err(Error::NotFound);
    };
    let pool = PoolId::from_bytes(pool).map_err(|_| Error::Corrupt("pool id"))?;
    let inserted = tx.execute(
        "INSERT INTO workers(id, pool_id, fingerprint, name, arch, capabilities, protocol, enrolled_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            presentation.worker.as_bytes(),
            pool.as_bytes(),
            presentation.fingerprint.0,
            presentation.name,
            arch_name(presentation.negotiated.arch),
            presentation.negotiated.capabilities.0 as i64,
            i64::from(presentation.negotiated.protocol.0),
            now.0
        ],
    );
    // A reused identifier or fingerprint is a second machine claiming to be
    // the first: refuse, and leave the enrollment unspent for the real one.
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
    Ok(Worker {
        id: presentation.worker,
        pool,
        fingerprint: presentation.fingerprint,
        name: presentation.name.to_owned(),
        negotiated: presentation.negotiated,
        enrolled: now,
        last_seen: None,
    })
}

/// Resolve a presented certificate fingerprint to a live worker: enrolled,
/// not revoked, in an active pool. One indexed lookup on the unique key. The
/// identity the worker generated is the only credential it ever presents.
pub fn authenticate(conn: &Connection, fingerprint: &Digest) -> Result<Worker> {
    let row = conn
        .prepare_cached(
            "SELECT w.id, w.pool_id, w.name, w.arch, w.capabilities, w.protocol,
                    w.enrolled_ms, w.last_seen_ms
             FROM workers w JOIN pools p ON p.id = w.pool_id
             WHERE w.fingerprint = ?1 AND w.revoked_ms IS NULL AND p.active = 1",
        )?
        .query_row([fingerprint.0], |r| {
            Ok((
                r.get::<_, [u8; 16]>(0)?,
                r.get::<_, [u8; 16]>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, i64>(5)?,
                r.get::<_, i64>(6)?,
                r.get::<_, Option<i64>>(7)?,
            ))
        })
        .optional()?
        .ok_or(Error::NotFound)?;
    Ok(Worker {
        id: WorkerId::from_bytes(row.0).map_err(|_| Error::Corrupt("worker id"))?,
        pool: PoolId::from_bytes(row.1).map_err(|_| Error::Corrupt("pool id"))?,
        fingerprint: *fingerprint,
        name: row.2,
        negotiated: Negotiated {
            protocol: ProtocolVersion(
                u16::try_from(row.5).map_err(|_| Error::Corrupt("workers.protocol"))?,
            ),
            capabilities: Capabilities(
                u64::try_from(row.4).map_err(|_| Error::Corrupt("workers.capabilities"))?,
            ),
            arch: parse_arch(&row.3).ok_or(Error::Corrupt("workers.arch"))?,
        },
        enrolled: UnixMillis(row.6),
        last_seen: row.7.map(UnixMillis),
    })
}

/// Whether recording liveness is worth a write yet.
pub fn seen_due(worker: &Worker, now: UnixMillis) -> bool {
    worker
        .last_seen
        .is_none_or(|last| now.0.saturating_sub(last.0) >= SEEN_RECORD_INTERVAL_MS)
}

/// Record a heartbeat. A revoked worker's heartbeat records nothing, and the
/// session that carried it will be refused on its next authentication.
pub fn seen(tx: &Transaction<'_>, worker: WorkerId, now: UnixMillis) -> Result<()> {
    tx.execute(
        "UPDATE workers SET last_seen_ms = ?2 WHERE id = ?1 AND revoked_ms IS NULL
         AND (last_seen_ms IS NULL OR last_seen_ms < ?2)",
        params![worker.as_bytes(), now.0],
    )?;
    Ok(())
}

/// Revoke a worker. Its current session is refused at its next authentication
/// and it can never enroll again under the same identity; W06 adds lease and
/// attempt reconciliation for work it held.
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

/// Live workers of a pool, for the scheduler and the operator. Platform
/// administration, or membership of a tenant the pool admits.
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
    let mut stmt = conn.prepare_cached(
        "SELECT id, fingerprint, name, arch, capabilities, protocol, enrolled_ms, last_seen_ms
         FROM workers WHERE pool_id = ?1 AND revoked_ms IS NULL ORDER BY enrolled_ms, id",
    )?;
    let rows = stmt.query_map([pool.as_bytes()], |r| {
        Ok((
            r.get::<_, [u8; 16]>(0)?,
            r.get::<_, [u8; 32]>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, i64>(4)?,
            r.get::<_, i64>(5)?,
            r.get::<_, i64>(6)?,
            r.get::<_, Option<i64>>(7)?,
        ))
    })?;
    rows.map(|row| {
        let row = row?;
        Ok(Worker {
            id: WorkerId::from_bytes(row.0).map_err(|_| Error::Corrupt("worker id"))?,
            pool,
            fingerprint: Digest(row.1),
            name: row.2,
            negotiated: Negotiated {
                protocol: ProtocolVersion(
                    u16::try_from(row.5).map_err(|_| Error::Corrupt("workers.protocol"))?,
                ),
                capabilities: Capabilities(
                    u64::try_from(row.4).map_err(|_| Error::Corrupt("workers.capabilities"))?,
                ),
                arch: parse_arch(&row.3).ok_or(Error::Corrupt("workers.arch"))?,
            },
            enrolled: UnixMillis(row.6),
            last_seen: row.7.map(UnixMillis),
        })
    })
    .collect()
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
