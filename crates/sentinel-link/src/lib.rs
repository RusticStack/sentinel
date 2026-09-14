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
//! Nothing here schedules work: offers, leases and logs are W02–W05. This crate
//! establishes *who is on the other end* and *whether they are still there*.

pub mod identity;
pub mod session;
pub mod tls;

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
