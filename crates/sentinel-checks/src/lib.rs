//! Durable external check delivery (G04).
//!
//! The store owns the outbox rows ([`sentinel_store::checks`]); this crate owns
//! delivery. [`Lane`] drains due rows through a [`Publisher`], which turns a
//! row into whatever a forge understands. Only the GitHub publisher exists
//! today ([`github::GithubChecks`]), and generic Git runs create no rows, so
//! no forge publisher is mandatory: the lane is simply idle.
//!
//! Publishing never blocks dispatch. A publication that fails transiently is
//! retried under the row's own attempt budget, a rate limit parks the whole
//! lane until it resets, and a permanent refusal is recorded with a reason an
//! operator can read. A publisher that read generation N can never overwrite
//! generation N+1: the store's guarded write names the sequence it read.

pub mod github;
pub mod lane;

pub use lane::{Batch, Config, Lane, Notice, Publish, Publisher};
