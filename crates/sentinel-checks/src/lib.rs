//! A publisher that read generation N can never overwrite generation N+1: the
//! store's guarded write names the sequence it read.

pub mod details;
pub mod github;
pub mod lane;
pub mod members;
pub mod reconcile;

pub use lane::{Batch, Config, Lane, Notice, Publish, Publisher};
pub use members::Members;
pub use reconcile::Reconcile;
