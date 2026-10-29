//! There is no certificate authority: each side pins the other's certificate fingerprint.

#[cfg(feature = "controller")]
mod admission;
#[cfg(feature = "controller")]
pub mod controller;
pub mod identity;
pub mod session;
pub mod tailcat;
pub mod tls;
pub mod worker;

use std::fmt;

#[derive(Debug)]
pub enum Error {
    Identity(String),
    Tls(String),
    Protocol(&'static str),
    Lost,
    /// A deliberate peer `close_notify`, not a failure: the worker reconnects on its shortest back-off.
    Closed,
    Rejected(session::Rejection),
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
            Self::Closed => f.write_str("peer closed the session"),
            Self::Rejected(why) => write!(f, "rejected ({why:?}): {}", why.reason()),
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
