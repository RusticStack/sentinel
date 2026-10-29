//! The API key, message bodies and recipient addresses never reach a log or an error.

use std::time::Duration;

use sentinel_core::{MailId, UnixMillis};

pub mod lane;
pub mod resend;

pub use lane::{Batch, Cause, Config as LaneConfig, Health, Lane, Notice};
pub use resend::{ApiKey, Resend, Sender};

pub struct Mail<'a> {
    pub id: MailId,
    pub to: &'a str,
    pub subject: &'a str,
    pub body: &'a str,
    pub now: UnixMillis,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Failure {
    Transient {
        why: String,
        retry_after: Option<Duration>,
    },
    /// The message is fine; the service refuses every message the same way (a key it will not accept, a sender it does not
    /// know). The row is left as it is and the lane pauses, so a fixed key delivers what was queued.
    Service(String),
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

pub trait Transport: Send {
    fn send(&mut self, mail: &Mail<'_>) -> Result<(), Failure>;
}

impl Transport for std::sync::Arc<Resend> {
    fn send(&mut self, mail: &Mail<'_>) -> Result<(), Failure> {
        self.deliver(mail)
    }
}
