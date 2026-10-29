//! A login token is never an installation token: it is never persisted or handed to a workload.
//! Only the immutable numeric account id is durable; logins, names and emails are renameable and reused.

pub mod app;
pub mod checks;
#[cfg(feature = "fake")]
pub mod fake;
pub mod http;
pub mod manifest;
pub mod oauth;
pub mod webhook;

use std::fmt;

/// Part of a stored primary key: changing it orphans existing links.
pub const PROVIDER: &str = "github";

pub(crate) fn now_ms() -> i64 {
    let nanos = time::OffsetDateTime::now_utc().unix_timestamp_nanos();
    i64::try_from(nanos / 1_000_000).unwrap_or(i64::MAX)
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Config(&'static str),
    Callback(&'static str),
    Denied(String),
    Transport(String),
    Response(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(what) => write!(f, "invalid {what}"),
            Self::Callback(what) => write!(f, "invalid callback {what}"),
            Self::Denied(code) => write!(f, "authorization denied: {code}"),
            Self::Transport(what) => write!(f, "github request failed: {what}"),
            Self::Response(what) => write!(f, "unexpected github response: {what}"),
        }
    }
}
impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;
