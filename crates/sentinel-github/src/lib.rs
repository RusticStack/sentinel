//! GitHub sign-in for humans (A04).
//!
//! Three things are kept apart here, deliberately:
//!
//! 1. **A sign-in identity** — proof from GitHub that a browser controls a
//!    particular GitHub account. That is all this crate establishes.
//! 2. **A Sentinel session or credential** — issued by `sentinel-store` only
//!    after admission policy has been applied. Authenticating at GitHub does
//!    not admit anybody.
//! 3. **A GitHub App installation token** — repository access for running jobs
//!    (Part 05). A user login token is never used as one, never persisted and
//!    never handed to a workload; it is read once and dropped.
//!
//! The only durable fact this crate produces is the immutable numeric GitHub
//! account ID. Logins, names and emails are renameable and reusable, so they
//! are metadata, never an identity key.

pub mod app;
pub mod http;
pub mod oauth;

use std::fmt;

/// Configured issuer key for [`sentinel-store`'s external identity table]. Its
/// value is part of a stored primary key; changing it orphans existing links.
///
/// [`sentinel-store`'s external identity table]: https://github.com/RusticStack/sentinel
pub const PROVIDER: &str = "github";

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// Endpoint or application configuration is unusable; never contains a secret.
    Config(&'static str),
    /// The callback's parameters were missing, duplicated, oversized or invalid.
    Callback(&'static str),
    /// The user (or GitHub) refused; carries GitHub's bounded error code.
    Denied(String),
    /// Transport, timeout, status or body-limit failure talking to GitHub.
    Transport(String),
    /// GitHub answered with something this contract does not accept.
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
