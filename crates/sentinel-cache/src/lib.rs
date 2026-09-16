//! Worker-local cache metadata: the scope paths every entry lives under,
//! the sealed-generation manifest format, and the explainable hit/miss
//! vocabulary the worker reports. See `docs/cache.md` for the design and
//! `docs/compatibility.md` for the versioned contract.
//!
//! Three cache classes exist because their validity rules differ
//! (`sentinel_protocol::cache::Class`): `downloads` are tool-addressed
//! blobs the installing tool validates itself, so they survive compatible
//! lockfile edits and prefix keys; `dependencies` are exact
//! materializations that may only serve a request whose recorded inputs
//! match completely; `compiler` entries live in a stable toolchain
//! namespace where the compiler performs input-level invalidation.
//!
//! Everything here is metadata. Corruption, incompatibility and truncation
//! are `Miss` values, never build failures. Clone backends, publication
//! leases and garbage collection are K02/K03; this crate owns what they
//! share: paths, formats and reasons.

pub mod attach;
pub mod clone;
pub mod gc;
pub mod lease;
pub mod manifest;
pub mod outcome;
pub mod publish;
pub mod restore;
pub mod scope;

pub use attach::{Attached, Stats, Target};
pub use clone::Backend;
pub use manifest::{Boundary, Compat, FileEntry, FilesBlob, Manifest, Request};
pub use outcome::{Hit, Miss, Outcome};
pub use scope::{Os, Platform, Scope};

/// The cache root inside the worker's data directory — every scope path
/// (`Scope::dir`) hangs under `<data_dir>/cache`.
pub const CACHE_DIR: &str = "cache";
