//! Callers write the record in the same writer transaction as the action it
//! describes, so an action is never committed without its record.

use rusqlite::{Connection, Transaction, params};
use sentinel_core::{GrantId, TenantId, UnixMillis, UserId};

use crate::{Error, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Action {
    CancelRun = 1,
    CancelJob = 2,
    RerunJob = 3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Actor {
    HostLocal,
    Credential(UserId),
    Session(UserId),
    OAuth(UserId, GrantId),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub at: UnixMillis,
    pub action: Action,
    pub target: [u8; 16],
    pub actor: Actor,
    pub client: Option<String>,
}

/// The OAuth client is copied in the same statement, so it survives grant purges.
pub fn record(
    tx: &Transaction<'_>,
    tenant: TenantId,
    action: Action,
    target: [u8; 16],
    actor: Actor,
    now: UnixMillis,
) -> Result<()> {
    let (user, via, grant) = match actor {
        Actor::HostLocal => (None, 0u8, None),
        Actor::Credential(user) => (Some(user), 1, None),
        Actor::Session(user) => (Some(user), 2, None),
        Actor::OAuth(user, grant) => (Some(user), 3, Some(grant)),
    };
    tx.prepare_cached(
        "INSERT INTO operation_audit(at_ms, tenant_id, action, target, actor_user_id, via,
            grant_id, client_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7,
            (SELECT client_id FROM oauth_grants WHERE id = ?7))",
    )?
    .execute(params![
        now.0,
        tenant.as_bytes(),
        action as u8,
        target,
        user.as_ref().map(UserId::as_bytes),
        via,
        grant.as_ref().map(GrantId::as_bytes),
    ])?;
    Ok(())
}

pub fn recent(conn: &Connection, tenant: TenantId, limit: u32) -> Result<Vec<Record>> {
    Ok(page(conn, tenant, None, limit)?
        .into_iter()
        .map(|(_, record)| record)
        .collect())
}

pub fn page(
    conn: &Connection,
    tenant: TenantId,
    before: Option<i64>,
    limit: u32,
) -> Result<Vec<(i64, Record)>> {
    let mut statement = conn.prepare_cached(
        "SELECT at_ms, action, target, actor_user_id, via, grant_id, client_id, seq
         FROM operation_audit WHERE tenant_id = ?1 AND seq < ?2 ORDER BY seq DESC LIMIT ?3",
    )?;
    let rows = statement.query_map(
        params![tenant.as_bytes(), before.unwrap_or(i64::MAX), limit],
        |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, u8>(1)?,
                r.get::<_, [u8; 16]>(2)?,
                r.get::<_, Option<[u8; 16]>>(3)?,
                r.get::<_, u8>(4)?,
                r.get::<_, Option<[u8; 16]>>(5)?,
                r.get::<_, Option<String>>(6)?,
                r.get::<_, i64>(7)?,
            ))
        },
    )?;
    let mut records = Vec::new();
    for row in rows {
        let (at, action, target, user, via, grant, client, seq) = row?;
        let action = match action {
            1 => Action::CancelRun,
            2 => Action::CancelJob,
            3 => Action::RerunJob,
            _ => return Err(Error::Corrupt("operation_audit.action")),
        };
        let user = user
            .map(|b| UserId::from_bytes(b).map_err(|_| Error::Corrupt("operation_audit.actor")))
            .transpose()?;
        let actor = match (via, user, grant) {
            (0, None, None) => Actor::HostLocal,
            (1, Some(user), None) => Actor::Credential(user),
            (2, Some(user), None) => Actor::Session(user),
            (3, Some(user), Some(grant)) => Actor::OAuth(
                user,
                GrantId::from_bytes(grant).map_err(|_| Error::Corrupt("operation_audit.grant"))?,
            ),
            _ => return Err(Error::Corrupt("operation_audit.via")),
        };
        records.push((
            seq,
            Record {
                at: UnixMillis(at),
                action,
                target,
                actor,
                client,
            },
        ));
    }
    Ok(records)
}
