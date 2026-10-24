//! Requests are acknowledged only after the delivery commits; no pipeline runs on the request path.
pub mod ingest;
pub mod lane;
pub mod poll;
pub mod resolve;
pub mod source;

pub use ingest::{Error, Github, Ingested};
pub use lane::{Batch, Lane, Settled, Waker};
pub use poll::{GitLister, ListRequest, Lister, Notice, Poll};
pub use resolve::{Fetch, FileRequest, GitFetch, Outcome, Resolver};
