//! Durable email delivery through Resend.
//!
//! The store owns the outbox rows ([`sentinel_store::email`]); this crate owns
//! delivery. [`Lane`] drains due messages through a [`Transport`], and
//! [`resend::Resend`] is the one transport: a bounded HTTPS client for the
//! fixed Resend API host (`POST https://api.resend.com/emails`) with no
//! redirects, no proxy, short deadlines and a bounded response.
//!
//! Nothing here runs in a request handler. A transient failure (a network
//! error, `429`, `5xx`) is retried under the row's own attempt budget with
//! backoff, honoring `Retry-After`; a refusal of the message or the account
//! (`4xx`) is recorded and not retried. The API key, message bodies and
//! recipient addresses never reach a log or an error.

use std::time::Duration;

use sentinel_core::{MailId, UnixMillis};

pub mod lane;
pub mod resend;

pub use lane::{Batch, Config as LaneConfig, Lane, Notice};
pub use resend::{ApiKey, Resend, Sender};

/// One message to send.
pub struct Mail<'a> {
    pub id: MailId,
    /// The recipient, in canonical form.
    pub to: &'a str,
    pub subject: &'a str,
    /// The plain-text body; the HTML part is derived from it.
    pub body: &'a str,
    pub now: UnixMillis,
}

/// Why a send failed. `Transient` is worth retrying (Resend is down, slow or
/// throttling, or the network is); `Permanent` is a refusal that retrying will
/// not change (a bad address, a bad key, a rejected message).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Failure {
    Transient {
        why: String,
        /// The earliest the service asked to be tried again, when it said.
        retry_after: Option<Duration>,
    },
    Permanent(String),
}

impl Failure {
    pub fn transient(why: impl Into<String>) -> Failure {
        Failure::Transient {
            why: why.into(),
            retry_after: None,
        }
    }
}

/// Something that can send one message.
pub trait Transport: Send {
    fn send(&mut self, mail: &Mail<'_>) -> Result<(), Failure>;
}
