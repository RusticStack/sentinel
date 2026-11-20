//! Artifact handoff: a job's worker takes an earlier job's published artifact from the controller.
//!
//! The bytes are the producer's own publication — the entries of its artifact manifest, at the digests the
//! publication recorded — so a handoff makes no second copy of anything and leaves the artifact's retention,
//! class and record exactly as the publication decided them. The worker asks for one artifact by name, the
//! controller answers with the artifact's shape and then its bodies, and the worker verifies every entry against
//! its digest before the artifact reaches the consuming job's workspace.

use serde::{Deserialize, Serialize};

use crate::limits::{MAX_ARTIFACT_CHUNK_BYTES, MAX_ARTIFACT_ENTRIES, MAX_ARTIFACT_PATH_BYTES};

/// The most one handoff artifact may carry. An artifact past this is refused before a body travels; the
/// publication itself enforces the same bound, so an artifact that could not exist is never fetched.
pub const MAX_BYTES: u64 = 1 << 30;
pub const MAX_ENTRIES: usize = MAX_ARTIFACT_ENTRIES;
pub const CHUNK_BYTES: usize = MAX_ARTIFACT_CHUNK_BYTES;

/// One entry as the producer's manifest states it: where it went inside the artifact, how long it is, what it
/// hashes to and the mode it was published with.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub path: String,
    pub len: u64,
    pub digest: [u8; 32],
    pub mode: u32,
}

impl Entry {
    /// Whether the controller may state this entry at all: a bound check before a byte of body arrives.
    pub fn well_formed(&self) -> bool {
        !self.path.is_empty()
            && self.path.len() <= MAX_ARTIFACT_PATH_BYTES
            && self.len <= MAX_BYTES
            && !self.path.starts_with('/')
            && !self
                .path
                .split('/')
                .any(|seg| seg == ".." || seg.is_empty())
    }
}

/// Why a handoff did not arrive. A consuming job whose artifact could not be delivered cannot run: the artifact is
/// an input it declared, not an optional result.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum Refusal {
    /// The attempt's job does not declare this artifact as a handoff.
    NotDeclared = 0,
    /// The producing job is not in the attempt's `needs`, or did not publish the artifact.
    Absent = 1,
    /// The worker does not hold this attempt, or its fence moved.
    Denied = 2,
    /// The controller could not read the publication, or the artifact is past its retention.
    Unavailable = 3,
}

impl Refusal {
    pub const fn code(self) -> u8 {
        self as u8
    }

    pub const fn from_code(code: u8) -> Option<Refusal> {
        Some(match code {
            0 => Refusal::NotDeclared,
            1 => Refusal::Absent,
            2 => Refusal::Denied,
            3 => Refusal::Unavailable,
            _ => return None,
        })
    }

    /// The verdict text a consuming job's preparation fails with.
    pub fn reason(self) -> &'static str {
        match self {
            Refusal::NotDeclared => "the job does not declare it",
            Refusal::Absent => "the producing job published no such artifact",
            Refusal::Denied => "the attempt was refused",
            Refusal::Unavailable => "the controller could not read the publication",
        }
    }
}

/// One frame of a handoff stream. The shape comes first, so a receiver refuses a past-bound artifact before any
/// body is written, and the entries are interleaved with their bodies in manifest order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Part {
    /// The artifact's whole shape: how many entries and how many bytes follow.
    Begin {
        entries: u32,
        bytes: u64,
    },
    Entry(Entry),
    Body {
        seq: u32,
        last: bool,
        bytes: Vec<u8>,
    },
    /// The artifact is complete: what travelled and the digest of its entry list as sent.
    End {
        entries: u32,
        bytes: u64,
        manifest: [u8; 32],
    },
    Refused(u8),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_entry_must_stay_inside_the_artifact_and_its_bounds() {
        let entry = |path: &str, len: u64| Entry {
            path: path.to_owned(),
            len,
            digest: [0; 32],
            mode: 0o644,
        };
        assert!(entry("dist/app", 10).well_formed());
        assert!(!entry("", 1).well_formed());
        assert!(!entry("/etc/passwd", 1).well_formed());
        assert!(!entry("dist/../../etc/passwd", 1).well_formed());
        assert!(!entry("dist//app", 1).well_formed());
        assert!(!entry("dist/app", MAX_BYTES + 1).well_formed());
        assert!(!entry(&"a".repeat(MAX_ARTIFACT_PATH_BYTES + 1), 1).well_formed());
    }

    #[test]
    fn a_refusal_code_round_trips_and_an_unknown_one_does_not() {
        for refusal in [
            Refusal::NotDeclared,
            Refusal::Absent,
            Refusal::Denied,
            Refusal::Unavailable,
        ] {
            assert_eq!(Refusal::from_code(refusal.code()), Some(refusal));
        }
        assert_eq!(Refusal::from_code(9), None);
    }

    const _: () = assert!(CHUNK_BYTES + 64 <= crate::limits::MAX_CONTROL_MESSAGE_BYTES);
    const _: () = assert!(MAX_ENTRIES > 0);
}
