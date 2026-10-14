//! Durable email delivery.
//!
//! The store owns the outbox rows ([`sentinel_store::email`]); this crate owns
//! delivery. [`Lane`] drains due messages through a [`Transport`], and
//! [`smtp::Smtp`] is the one transport: a small, bounded SMTP submission
//! client (implicit TLS or STARTTLS, `AUTH PLAIN`/`LOGIN`, one message per
//! connection) with its own deadlines, reply and message size limits.
//!
//! Nothing here runs in a request handler. A transient failure is retried
//! under the row's own attempt budget with backoff; a refusal by the relay of
//! the message itself is recorded and not retried. Message bodies and
//! credentials never reach a log or an error.

pub mod lane;
pub mod smtp;

pub use lane::{Batch, Config as LaneConfig, Lane, Notice};
pub use smtp::{Config, Credentials, Failure, Mail, Smtp, Tls, Transport};
