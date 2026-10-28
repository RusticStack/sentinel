//! `downloads` survive compatible lockfile edits, `dependencies` need every recorded input to match, and `compiler` relies on input-level invalidation.
//! Corruption, incompatibility and truncation are misses, never build failures.

pub mod attach;
pub mod clone;
mod confined;
pub mod cost;
pub mod gc;
pub mod lease;
pub mod manifest;
pub mod outcome;
pub mod publish;
pub mod remote;
pub mod restore;
pub mod scope;

pub use attach::{Attached, Committed, Costly, Stats, Target};
pub use clone::Backend;
pub use cost::CostBook;
pub use manifest::{Boundary, Compat, FileEntry, FilesBlob, Manifest, Request};
pub use outcome::{Hit, Miss, Outcome};
pub use scope::{Os, Platform, Scope};

pub const CACHE_DIR: &str = "cache";
