//! The worker link (W01): a worker-generated TLS identity, mutually
//! authenticated persistent sessions pinned in both directions, bounded
//! framing, hello/negotiation and heartbeat.
//!
//! There is no certificate authority. A worker generates its own certificate;
//! the controller learns its fingerprint at enrollment and afterwards accepts
//! exactly that fingerprint. The worker, in turn, is handed the controller's
//! fingerprint with its enrollment and accepts exactly that server. Identity is
//! a key you hold, not a name somebody vouched for.
//!
//! W02 adds the dispatch loop on top: a `controller` (behind the feature of
//! that name, which brings in the store) that listens, admits, places work
//! and pushes fenced offers; and a `worker` loop that reconnects with
//! back-off, answers offers and renews its leases on every heartbeat.

#[cfg(feature = "controller")]
pub mod controller;
pub mod identity;
pub mod session;
pub mod tls;
pub mod worker;

use std::fmt;

#[derive(Debug)]
pub enum Error {
    /// Certificate or key material could not be generated, parsed or stored.
    Identity(String),
    /// TLS configuration or handshake failure. Never carries key material.
    Tls(String),
    /// The peer sent something outside the protocol: too large, undecodable,
    /// or out of sequence. The session is closed.
    Protocol(&'static str),
    /// The peer stopped answering within the heartbeat deadline.
    Lost,
    /// The controller refused the hello; the worker must not retry unchanged.
    Rejected(session::Rejection),
    /// The controller's own store refused or failed; the session ends and the
    /// worker reconnects. Never carries the store's detail across the wire.
    Internal(&'static str),
    Io(std::io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Identity(what) => write!(f, "identity: {what}"),
            Self::Tls(what) => write!(f, "tls: {what}"),
            Self::Protocol(what) => write!(f, "protocol violation: {what}"),
            Self::Lost => f.write_str("peer stopped answering"),
            Self::Rejected(why) => write!(f, "rejected: {why:?}"),
            Self::Internal(what) => write!(f, "controller: {what}"),
            Self::Io(e) => write!(f, "io: {e}"),
        }
    }
}
impl std::error::Error for Error {}
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
