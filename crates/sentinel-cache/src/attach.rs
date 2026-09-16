//! The carrier between restore (K02) and publish (K03): what one declared
//! `cache:` entry became for one attempt. Preparation fills one per
//! declaration; finalization reads them to publish the job's writes.

use std::path::PathBuf;

use crate::{Compat, Outcome, Scope};

/// One declared cache, resolved for a job.
pub struct Attached {
    /// The pipeline's cache name.
    pub name: String,
    /// The scope the entry lives under — every boundary dimension
    /// resolved for this run.
    pub scope: Scope,
    /// The rendered user key (`hash_files` evaluated against the pinned
    /// checkout, so it is evaluated only after it lands).
    pub key: String,
    /// The class's compatibility inputs for this request — what a
    /// published manifest will record.
    pub compat: Compat,
    /// The generation the private view was cloned from; `None` on a miss.
    pub generation: Option<String>,
    /// What the lookup answered — hit, or the explainable miss reason.
    pub outcome: Outcome,
    /// The job-private writable directory the declared paths resolve to.
    /// On a hit this is the generation's clone; on a miss a fresh empty
    /// directory, so a job always sees a writable cache path.
    pub dir: PathBuf,
}
