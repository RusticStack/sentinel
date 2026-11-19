//! The tenant storage threshold notice: one per crossing, to the tenant's administrators through the durable mail
//! outbox when mail is configured and through the tenant's storage page otherwise, and one audit row.
//!
//! A crossing is remembered by `storage_notices`, the row that arms the next notice: it is written in the same
//! transaction that queues the mail, so a controller that restarts finds it and tells nobody twice, and it is
//! deleted once usage falls back under the re-arm line, so an oscillating tenant is told once per crossing. The
//! pass that looks for crossings is the API's (`sentinel_api::notices`), off the request path: usage is written
//! by triggers from many places, so nothing on a request path can notice it without paying for every request.
//!
//! The line a crossing is judged against is the tenant's own soft threshold (L03's `retention::standing`), never a
//! second definition of it, and nothing is refused here: the thresholds themselves are the store's policy.

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sentinel_auth::sealed::Key;
use sentinel_core::{TenantId, UnixMillis};

use crate::{
    Error, Result, email, local_auth,
    local_auth::Event,
    retention::{self, Deployment, State},
};

/// The share of its quota usage has to fall back under before the next crossing is told: the band between this
/// and the tenant's soft threshold is the hysteresis that keeps an oscillating tenant to one notice.
pub const REARM_PERCENT: u8 = 75;
/// Administrators one crossing mails, so a large organization cannot make one pass queue thousands of messages.
pub const MAX_RECIPIENTS: i64 = 32;
/// A notice is about storage now: one that could not be delivered within a day is given up by the outbox.
const TTL_MS: i64 = 24 * 3_600_000;

/// The percentage usage has to fall back under to re-arm, given the tenant's soft threshold. A tenant whose
/// threshold is set below the re-arm line tightens it to just under its own line, so the band can never invert
/// into a notice per pass.
const fn rearm_percent(soft_percent: u8) -> u8 {
    let below = soft_percent.saturating_sub(1);
    if below == 0 {
        1
    } else if below < REARM_PERCENT {
        below
    } else {
        REARM_PERCENT
    }
}

/// A tenant that reached its soft threshold and has not been told since usage last fell back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Crossing {
    pub tenant: TenantId,
    pub slug: String,
}

/// How the notice reached the tenant's administrators. Stored as `storage_notices.delivery`: never renumber.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Delivery {
    Mail = 1,
    InApp = 2,
}

impl Delivery {
    const fn from_code(code: i64) -> Option<Delivery> {
        match code {
            1 => Some(Delivery::Mail),
            2 => Some(Delivery::InApp),
            _ => None,
        }
    }
}

/// What the tenant's storage page says about the last crossing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Notice {
    pub threshold_percent: u8,
    pub used_bytes: u64,
    pub limit_bytes: u64,
    pub delivery: Delivery,
    pub notified_ms: i64,
}

/// The tenants standing at or past their soft threshold that no notice stands for: every tenant one keyed row,
/// with the notice that would suppress it by its own key. The thresholds are the tenant's own, as
/// `retention::standing` reads them, so a notice can never disagree with the report beside it.
pub fn crossings(conn: &Connection, d: &Deployment, limit: u32) -> Result<Vec<Crossing>> {
    let mut statement = conn.prepare_cached(
        "SELECT u.tenant_id, t.slug, u.bytes + u.log_bytes, p.quota_bytes, p.soft_percent, p.hard_percent
         FROM tenant_usage u JOIN tenants t ON t.id = u.tenant_id AND t.active = 1
         LEFT JOIN storage_policies p ON p.tenant_id = u.tenant_id AND p.repo_id = X''
         WHERE NOT EXISTS(SELECT 1 FROM storage_notices n WHERE n.tenant_id = u.tenant_id)",
    )?;
    let rows = statement.query_map([], |r| {
        Ok((
            r.get::<_, [u8; 16]>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, i64>(2)?.max(0) as u64,
            r.get::<_, Option<i64>>(3)?,
            r.get::<_, Option<i64>>(4)?,
            r.get::<_, Option<i64>>(5)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (tenant, slug, used, quota, soft, hard) = row?;
        let (soft, hard) = retention::thresholds(
            d,
            soft.map(|p| p.clamp(1, 100) as u8),
            hard.map(|p| p.clamp(1, 100) as u8),
        );
        let quota = quota.map_or(d.tenant_quota_bytes, |q| q.max(0) as u64);
        if retention::state(used, quota, soft, hard) == State::Ok {
            continue;
        }
        out.push(Crossing {
            tenant: TenantId::from_bytes(tenant).map_err(|_| Error::Corrupt("tenant_id"))?,
            slug,
        });
        if out.len() as u32 >= limit {
            break;
        }
    }
    Ok(out)
}

/// The tenants whose usage fell back under the re-arm line, or whose limit was removed, so their notice stops
/// keeping the next crossing quiet. This reads the notice rows only, which are as many as the tenants over the line.
pub fn recovered(conn: &Connection, d: &Deployment, limit: u32) -> Result<Vec<TenantId>> {
    let mut statement = conn.prepare_cached(
        "SELECT n.tenant_id, COALESCE(u.bytes, 0) + COALESCE(u.log_bytes, 0), p.quota_bytes,
             p.soft_percent, p.hard_percent
         FROM storage_notices n LEFT JOIN tenant_usage u ON u.tenant_id = n.tenant_id
         LEFT JOIN storage_policies p ON p.tenant_id = n.tenant_id AND p.repo_id = X''",
    )?;
    let rows = statement.query_map([], |r| {
        Ok((
            r.get::<_, [u8; 16]>(0)?,
            r.get::<_, i64>(1)?.max(0) as u64,
            r.get::<_, Option<i64>>(2)?,
            r.get::<_, Option<i64>>(3)?,
            r.get::<_, Option<i64>>(4)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (tenant, used, quota, soft, hard) = row?;
        let (soft, _) = retention::thresholds(
            d,
            soft.map(|p| p.clamp(1, 100) as u8),
            hard.map(|p| p.clamp(1, 100) as u8),
        );
        let quota = quota.map_or(d.tenant_quota_bytes, |q| q.max(0) as u64);
        if used >= retention::limit_bytes(quota, rearm_percent(soft)) && quota > 0 {
            continue;
        }
        out.push(TenantId::from_bytes(tenant).map_err(|_| Error::Corrupt("tenant_id"))?);
        if out.len() as u32 >= limit {
            break;
        }
    }
    Ok(out)
}

/// The tenant's administrators a notice reaches: people with a verified address, never a service account.
fn recipients(conn: &Connection, tenant: TenantId) -> Result<Vec<String>> {
    let mut statement = conn.prepare_cached(
        "SELECT u.email FROM memberships m JOIN users u ON u.id = m.user_id
         WHERE m.tenant_id = ?1 AND m.role = 3 AND u.kind = 0 AND u.active = 1
           AND u.email IS NOT NULL AND u.email_verified_ms IS NOT NULL
         ORDER BY u.id LIMIT ?2",
    )?;
    let rows = statement.query_map(params![tenant.as_bytes(), MAX_RECIPIENTS], |r| {
        r.get::<_, String>(0)
    })?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

fn bytes_text(bytes: u64) -> String {
    for (unit, scale) in [("GiB", 1u64 << 30), ("MiB", 1 << 20), ("KiB", 1 << 10)] {
        if bytes >= scale {
            return format!("{} {unit}", bytes / scale);
        }
    }
    format!("{bytes} bytes")
}

fn percent(used: u64, limit: u64) -> u64 {
    u64::try_from(u128::from(used) * 100 / u128::from(limit.max(1))).unwrap_or(u64::MAX)
}

fn message(slug: &str, standing: &retention::Standing) -> (String, String) {
    let at = percent(standing.used, standing.quota_bytes);
    let subject = format!("{slug} is at {at}% of its Sentinel storage quota");
    let body = format!(
        "Storage for {slug} has reached {at}% of its quota: {} of {}.\n\
         \n\
         At {}% of the quota its remote cache is evicted first, then artifact publications and uploads are \
         refused. Logs stay counted and are never refused, so retention is what reclaims them.\n\
         \n\
         Raise the tenant's quota, or remove what it no longer needs, from its storage page.\n\
         \n\
         This is the only message until use falls back under {}% and reaches {}% again.\n",
        bytes_text(standing.used),
        bytes_text(standing.quota_bytes),
        standing.hard_percent,
        rearm_percent(standing.soft_percent),
        standing.soft_percent,
    );
    (subject, body)
}

/// Writes the notice for `crossing` and, when mail is configured, queues one message per administrator of the
/// tenant — all in this one transaction. Usage is judged again here, so a crossing that fell back between the read
/// that found it and this write is not told, and a notice another writer already wrote makes this a no-op.
/// Returns `None` when nothing was written.
pub fn record(
    tx: &Transaction<'_>,
    key: Option<&Key>,
    d: &Deployment,
    crossing: &Crossing,
    now: UnixMillis,
) -> Result<Option<Delivery>> {
    let tenant = crossing.tenant;
    let standing = retention::standing(tx, d, tenant)?;
    if standing.state == State::Ok || standing.quota_bytes == 0 {
        return Ok(None);
    }
    let claimed = tx
        .prepare_cached(
            "INSERT INTO storage_notices(tenant_id, threshold_percent, used_bytes, limit_bytes, delivery,
                 notified_ms)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6) ON CONFLICT(tenant_id) DO NOTHING",
        )?
        .execute(params![
            tenant.as_bytes(),
            standing.soft_percent,
            standing.used as i64,
            standing.quota_bytes as i64,
            Delivery::InApp as u8,
            now.0
        ])?;
    if claimed == 0 {
        return Ok(None);
    }
    let mut queued = 0;
    if let Some(key) = key
        && email::delivery_enabled(tx)?
    {
        let (subject, body) = message(&crossing.slug, &standing);
        for address in recipients(tx, tenant)? {
            let outgoing = email::Outgoing {
                kind: email::Kind::StorageNotice,
                recipient: &address,
                subject: &subject,
                body: &body,
                ttl_ms: TTL_MS,
            };
            queued += u32::from(email::enqueue(tx, key, &outgoing, now)?);
        }
        if queued > 0 {
            tx.prepare_cached(
                "UPDATE storage_notices SET delivery = ?2 WHERE tenant_id = ?1 AND delivery != ?2",
            )?
            .execute(params![tenant.as_bytes(), Delivery::Mail as u8])?;
        }
    }
    local_auth::audit(
        tx,
        Event::StorageNotice,
        None,
        None,
        false,
        Some(&format!(
            "{} at {}%",
            crossing.slug,
            percent(standing.used, standing.quota_bytes)
        )),
    )?;
    Ok(Some(if queued > 0 {
        Delivery::Mail
    } else {
        Delivery::InApp
    }))
}

/// Deletes the notices that would stop the next crossing from being told. Returns how many there were.
pub fn rearm(tx: &Transaction<'_>, tenants: &[TenantId]) -> Result<u32> {
    let mut statement = tx.prepare_cached("DELETE FROM storage_notices WHERE tenant_id = ?1")?;
    let mut removed = 0;
    for tenant in tenants {
        removed += statement.execute([tenant.as_bytes()])? as u32;
    }
    Ok(removed)
}

/// The notice standing for the tenant's last crossing, for its storage page.
pub fn notice(conn: &Connection, tenant: TenantId) -> Result<Option<Notice>> {
    let row = conn
        .prepare_cached(
            "SELECT threshold_percent, used_bytes, limit_bytes, delivery, notified_ms
             FROM storage_notices WHERE tenant_id = ?1",
        )?
        .query_row([tenant.as_bytes()], |r| {
            Ok((
                r.get::<_, u8>(0)?,
                r.get::<_, i64>(1)? as u64,
                r.get::<_, i64>(2)? as u64,
                r.get::<_, i64>(3)?,
                r.get::<_, i64>(4)?,
            ))
        })
        .optional()?;
    row.map(
        |(threshold_percent, used_bytes, limit_bytes, code, notified_ms)| {
            Ok(Notice {
                threshold_percent,
                used_bytes,
                limit_bytes,
                delivery: Delivery::from_code(code)
                    .ok_or(Error::Corrupt("storage_notices.delivery"))?,
                notified_ms,
            })
        },
    )
    .transpose()
}
