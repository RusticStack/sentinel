//! The device authorization flow's durable half (O03): pending requests,
//! approval or denial by a signed-in account, and one-time redemption.
//!
//! Stub: the signatures are the contract; Unit C implements the bodies.

use rusqlite::Connection;
use sentinel_auth::secret::Secret;
use sentinel_core::{
    RepoId, TenantId, UnixMillis, UserId,
    auth::{Audience, Scopes},
};

use super::Minted;
use crate::{Error, Result, Store};

/// A new pending request: the device code (for the polling client only)
/// and the canonical user code (8 characters, no dash).
#[derive(Debug)]
pub struct DeviceStart {
    pub device: Secret,
    pub user_code: String,
    pub expires: UnixMillis,
    pub interval_ms: i64,
}

/// Open a pending device request.
pub fn begin(
    store: &Store,
    client_id: &str,
    scopes: Scopes,
    audience: Audience,
    now: UnixMillis,
) -> Result<DeviceStart> {
    let _ = (store, client_id, scopes, audience, now);
    Err(Error::InvalidInput("not implemented"))
}

/// What the approval page shows for a pending user code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceView {
    pub client_name: String,
    pub scopes: Scopes,
    pub expires: UnixMillis,
}

/// Look up a pending request by its canonical user code.
pub fn view(conn: &Connection, user_code: &str, now: UnixMillis) -> Result<DeviceView> {
    let _ = (conn, user_code, now);
    Err(Error::InvalidInput("not implemented"))
}

/// The signed-in account's answer.
#[derive(Clone, Copy, Debug)]
pub enum Decision {
    Approve {
        scopes: Scopes,
        tenant: Option<TenantId>,
        repo: Option<RepoId>,
    },
    Deny,
}

/// Record a decision on a pending request.
pub fn decide(
    store: &Store,
    user_code: &str,
    user: UserId,
    d: Decision,
    now: UnixMillis,
) -> Result<()> {
    let _ = (store, user_code, user, d, now);
    Err(Error::InvalidInput("not implemented"))
}

/// What a poll finds.
#[derive(Debug)]
pub enum Poll {
    Pending,
    Denied,
    Expired,
    Issued(Minted),
}

/// Poll a request; issues the grant exactly once after approval.
pub fn poll(store: &Store, client_id: &str, device: &Secret, now: UnixMillis) -> Result<Poll> {
    let _ = (store, client_id, device, now);
    Err(Error::InvalidInput("not implemented"))
}
