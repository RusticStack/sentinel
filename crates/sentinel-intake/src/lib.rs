//! Durable event intake (G02).
//!
//! Two authenticated shapes feed one store: a generic relay submits a
//! ref-update document under a repository hook secret, and GitHub delivers a
//! `push` webhook signed with the App's webhook secret. Both become
//! deduplicated, tenant-owned deliveries inside one writer transaction, and
//! both are acknowledged only after that commit. Nothing here runs a
//! pipeline: the [`Lane`] resolves deliveries asynchronously and bounded.
pub mod ingest;
pub mod lane;

pub use ingest::{Error, Github, Ingested};
pub use lane::{Batch, Lane, Settled, Waker};
