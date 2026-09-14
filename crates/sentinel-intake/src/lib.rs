//! Durable event intake and resolution (G02/G03).
//!
//! Two authenticated shapes feed one store: a generic relay submits a
//! ref-update document under a repository hook secret, and GitHub delivers a
//! `push` or `pull_request` webhook signed with the App's webhook secret. Both
//! become deduplicated, tenant-owned deliveries inside one writer transaction,
//! and both are acknowledged only after that commit.
//!
//! Nothing here runs a pipeline on the request path. The [`Lane`] validates
//! deliveries against their source binding and then, through the [`Resolver`],
//! mint source access, reads the pipeline from the policy-selected pinned
//! revision, compiles it and creates one immutable run — or settles an
//! explicit outcome an operator and G04's Checks publisher can read.
pub mod ingest;
pub mod lane;
pub mod resolve;
pub mod source;

pub use ingest::{Error, Github, Ingested};
pub use lane::{Batch, Lane, Settled, Waker};
pub use resolve::{Fetch, FileRequest, GitFetch, Outcome, Resolver};
