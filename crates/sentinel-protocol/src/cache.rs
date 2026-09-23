//! Cache classification shared by the pipeline schema, the worker link and
//! the worker-local cache store: which validity rule a declared `cache:`
//! entry follows, and which trust boundary a job's cache state lives behind.
//! See `docs/cache.md` for the design.

use serde::{Deserialize, Serialize};

/// What a `cache:` entry stores. Each class has its own validity rule —
/// the layout, manifests and miss reasons treat them separately so a
/// permissive class never loosens an exact one (docs/cache.md).
///
/// Wire form is one byte (`to_u8`); serde/JSON and `.sentinel.yml` use the
/// lowercase name.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum Class {
    /// Tool-addressed blob stores (package registry responses, fetched
    /// archives): the tool validates content by its own digest/protocol, so
    /// entries survive lockfile edits and may use prefix/restore keys.
    Downloads = 0,
    /// Exact materializations of a dependency set: usable only under a
    /// complete compatibility key. The default — the safest reading of a
    /// declaration that names no class.
    #[default]
    Dependencies = 1,
    /// Compiler intermediates in a stable toolchain/platform namespace;
    /// the compiler owns input-level invalidation, so entries persist
    /// across source and lockfile edits.
    Compiler = 2,
}

impl Class {
    /// Every value, in wire-code order.
    pub const ALL: [Class; 3] = [Self::Downloads, Self::Dependencies, Self::Compiler];

    /// The wire code.
    pub const fn to_u8(self) -> u8 {
        self as u8
    }
    /// Decode a wire code; `None` for anything this build does not know —
    /// callers reject rather than guess a class.
    pub const fn from_u8(code: u8) -> Option<Class> {
        match code {
            0 => Some(Self::Downloads),
            1 => Some(Self::Dependencies),
            2 => Some(Self::Compiler),
            _ => None,
        }
    }
    /// The lowercase name used in `.sentinel.yml`, JSON and the scope path.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Downloads => "downloads",
            Self::Dependencies => "dependencies",
            Self::Compiler => "compiler",
        }
    }
    /// Parse an `as_str` name; `None` for anything else so the caller can
    /// report the accepted values instead of echoing the bad one.
    pub fn of_name(name: &str) -> Option<Class> {
        Self::ALL.iter().copied().find(|c| c.as_str() == name)
    }
}

impl std::fmt::Display for Class {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The trust boundary a job's cache scopes live behind.
///
/// The derivation ([`Trust::derive`], docs/cache.md) keys trust to who could
/// have produced the run's content, not merely to its event name: only a
/// `push`/`tag` that arrived through verified intake for a ref the
/// repository's binding names exactly is `Protected`; a `pull_request` run
/// is `PullRequest`; everything else — manual API runs (caller-chosen
/// source and pipeline), pushes to refs a wildcard admits, runs of an
/// unbound repository, or no recorded provenance — is `Unprotected`. Each
/// class reads and writes only its own scope, so neither untrusted class
/// can plant state a protected build restores. The store computes this
/// once and every consumer uses the same rule.
///
/// Wire form is one byte (`to_u8`); serde/JSON uses the snake_case name.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum Trust {
    /// Verified pushes and tags to a ref the binding names exactly: the
    /// protected cache scope.
    Protected = 0,
    /// Pull-request runs. Also the default when a wire did not carry the
    /// class — the safer reading, since it can never touch protected state.
    #[default]
    PullRequest = 1,
    /// Runs whose content an insider chose without the protected ref's
    /// review: manual runs, pushes to wildcard-admitted refs, unbound
    /// repositories. Protocol 8; an older worker is sent `PullRequest`.
    Unprotected = 2,
}

impl Trust {
    /// Every value, in wire-code order.
    pub const ALL: [Trust; 3] = [Self::Protected, Self::PullRequest, Self::Unprotected];

    /// The trust class of a run. `event` is the recorded trigger;
    /// `verified_intake` says the run came from an authenticated delivery
    /// (a webhook or ref poll), not the API; `protected_ref` says the
    /// repository's live binding names the run's ref exactly, without a
    /// wildcard.
    pub fn derive(event: &str, verified_intake: bool, protected_ref: bool) -> Trust {
        match event {
            "pull_request" => Trust::PullRequest,
            "push" | "tag" if verified_intake && protected_ref => Trust::Protected,
            _ => Trust::Unprotected,
        }
    }

    /// The class to send a peer that negotiated `protocol`: before 8 there
    /// is no `Unprotected`, and such a job is scoped to `PullRequest` — the
    /// class that can never touch protected state.
    pub const fn for_protocol(self, protocol: u16) -> Trust {
        match self {
            Self::Unprotected if protocol < 8 => Self::PullRequest,
            other => other,
        }
    }

    /// Whether a transfer naming `requested` is within a job of class
    /// `self`: the same class, or the `PullRequest` an older worker was
    /// told to use for an unprotected job.
    pub const fn admits(self, requested: Trust) -> bool {
        matches!(
            (self, requested),
            (Self::Protected, Self::Protected)
                | (Self::PullRequest, Self::PullRequest)
                | (Self::Unprotected, Self::Unprotected | Self::PullRequest)
        )
    }

    /// The wire code.
    pub const fn to_u8(self) -> u8 {
        self as u8
    }
    /// Decode a wire code; `None` for anything this build does not know —
    /// a trust byte that cannot be decoded is a protocol error, never a
    /// guess, since guessing `Protected` would cross the boundary.
    pub const fn from_u8(code: u8) -> Option<Trust> {
        match code {
            0 => Some(Self::Protected),
            1 => Some(Self::PullRequest),
            2 => Some(Self::Unprotected),
            _ => None,
        }
    }
    /// The lowercase name used in JSON and the scope path.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Protected => "protected",
            Self::PullRequest => "pull_request",
            Self::Unprotected => "unprotected",
        }
    }
    /// Parse an `as_str` name.
    pub fn of_name(name: &str) -> Option<Trust> {
        Self::ALL.iter().copied().find(|t| t.as_str() == name)
    }
}

impl std::fmt::Display for Trust {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn class_codes_and_names_round_trip() {
        for class in Class::ALL {
            assert_eq!(Class::from_u8(class.to_u8()), Some(class));
            assert_eq!(Class::of_name(class.as_str()), Some(class));
            let json = serde_json::to_string(&class).unwrap();
            assert_eq!(json, format!("\"{}\"", class.as_str()));
            assert_eq!(serde_json::from_str::<Class>(&json).unwrap(), class);
        }
        assert_eq!(Class::from_u8(3), None);
        assert_eq!(Class::of_name("Compiler"), None, "lowercase only");
        assert_eq!(Class::of_name(""), None);
        assert_eq!(Class::default(), Class::Dependencies);
    }

    #[test]
    fn trust_codes_names_and_event_derivation() {
        for trust in Trust::ALL {
            assert_eq!(Trust::from_u8(trust.to_u8()), Some(trust));
            assert_eq!(Trust::of_name(trust.as_str()), Some(trust));
            let json = serde_json::to_string(&trust).unwrap();
            assert_eq!(json, format!("\"{}\"", trust.as_str()));
            assert_eq!(serde_json::from_str::<Trust>(&json).unwrap(), trust);
        }
        assert_eq!(Trust::from_u8(3), None);
        assert_eq!(Trust::of_name("protected "), None);
        assert_eq!(Trust::default(), Trust::PullRequest);
    }

    /// P07-2: protected state is written only by verified pushes/tags to a
    /// ref the binding names exactly; manual runs, wildcard-admitted refs
    /// and unknown events never are.
    #[test]
    fn only_verified_protected_refs_are_protected() {
        assert_eq!(Trust::derive("push", true, true), Trust::Protected);
        assert_eq!(Trust::derive("tag", true, true), Trust::Protected);
        for (event, verified, exact) in [
            ("push", true, false),
            ("push", false, true),
            ("tag", false, false),
            ("manual", true, true),
            ("manual", false, false),
            ("", true, true),
            ("merge_queue", true, true),
        ] {
            assert_eq!(
                Trust::derive(event, verified, exact),
                Trust::Unprotected,
                "{event} {verified} {exact}"
            );
        }
        for verified in [true, false] {
            assert_eq!(
                Trust::derive("pull_request", verified, true),
                Trust::PullRequest
            );
        }
    }

    #[test]
    fn older_peers_get_the_pull_request_scope_for_unprotected_jobs() {
        assert_eq!(Trust::Unprotected.for_protocol(7), Trust::PullRequest);
        assert_eq!(Trust::Unprotected.for_protocol(8), Trust::Unprotected);
        assert_eq!(Trust::Protected.for_protocol(6), Trust::Protected);
        assert!(Trust::Unprotected.admits(Trust::PullRequest));
        assert!(!Trust::Unprotected.admits(Trust::Protected));
        assert!(!Trust::PullRequest.admits(Trust::Unprotected));
        assert!(!Trust::PullRequest.admits(Trust::Protected));
        assert!(Trust::Protected.admits(Trust::Protected));
    }
}
