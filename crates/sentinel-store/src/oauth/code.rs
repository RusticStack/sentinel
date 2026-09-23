//! The authorization-code flow's durable half (O01): consent choices, code
//! issuance on approval, and the single-use, PKCE-bound exchange.
//!
//! Stub: the signatures are the contract; Unit B implements the bodies.

use rusqlite::Connection;
use sentinel_auth::secret::Secret;
use sentinel_core::{
    RepoId, TenantId, UnixMillis, UserId,
    auth::{Audience, Role, Scopes},
};

use super::Minted;
use crate::{Error, Result, Store};

/// A tenant the consenting account may narrow a grant to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsentChoice {
    pub tenant: TenantId,
    pub slug: String,
    pub role: Role,
}

/// The account's active memberships, at most 100.
pub fn consent_choices(conn: &Connection, user: UserId) -> Result<Vec<ConsentChoice>> {
    let _ = (conn, user);
    Err(Error::InvalidInput("not implemented"))
}

/// What the account approved on the consent page.
#[derive(Clone, Copy, Debug)]
pub struct Approval<'a> {
    pub client_id: &'a str,
    pub redirect_uri: &'a str,
    pub code_challenge: &'a str,
    pub user: UserId,
    pub scopes: Scopes,
    pub tenant: Option<TenantId>,
    pub repo: Option<RepoId>,
    pub audience: Audience,
}

/// Record an approved request and return its authorization code.
pub fn approve(store: &Store, a: &Approval<'_>, now: UnixMillis) -> Result<Secret> {
    let _ = (store, a, now);
    Err(Error::InvalidInput("not implemented"))
}

/// Why an exchange produced no tokens.
#[derive(Debug)]
pub enum CodeError {
    /// Unknown, expired, another client's, wrong redirect or wrong verifier.
    Invalid,
    /// A spent code was presented again; its grant is revoked (reason 3).
    Replay,
    Store(Error),
}

/// Exchange a code for the first token pair of a new grant.
pub fn exchange(
    store: &Store,
    client_id: &str,
    code: &Secret,
    redirect_uri: &str,
    verifier: &str,
    now: UnixMillis,
) -> std::result::Result<Minted, CodeError> {
    let _ = (store, client_id, code, redirect_uri, verifier, now);
    Err(CodeError::Store(Error::InvalidInput("not implemented")))
}
