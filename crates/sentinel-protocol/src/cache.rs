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
/// v1 derivation (`of_event`): a run recorded under the `pull_request`
/// event is `PullRequest`; every other trigger — `push`, `tag`, `manual`,
/// or a run with no recorded provenance — is `Protected`. Pull-request
/// state is content a fork can influence, so it is never allowed to poison
/// protected builds; the store computes this once from recorded provenance
/// and every consumer uses the same rule.
///
/// Wire form is one byte (`to_u8`); serde/JSON uses the snake_case name.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum Trust {
    /// Trusted events (push, tag, manual): the protected cache scope.
    Protected = 0,
    /// Pull-request runs. Also the default when a wire did not carry the
    /// class — the safer reading, since it can never touch protected state.
    #[default]
    PullRequest = 1,
}

impl Trust {
    /// Every value, in wire-code order.
    pub const ALL: [Trust; 2] = [Self::Protected, Self::PullRequest];

    /// The v1 derivation: `pull_request` runs are untrusted for cache
    /// purposes; everything else is protected.
    pub fn of_event(event: &str) -> Trust {
        match event {
            "pull_request" => Trust::PullRequest,
            _ => Trust::Protected,
        }
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
            _ => None,
        }
    }
    /// The lowercase name used in JSON and the scope path.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Protected => "protected",
            Self::PullRequest => "pull_request",
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
        assert_eq!(Trust::from_u8(2), None);
        assert_eq!(Trust::of_name("protected "), None);
        // The v1 rule: only pull_request is untrusted; everything else is
        // protected, including events added later.
        assert_eq!(Trust::of_event("pull_request"), Trust::PullRequest);
        for event in ["push", "tag", "manual", "", "merge_queue"] {
            assert_eq!(Trust::of_event(event), Trust::Protected, "{event}");
        }
        assert_eq!(Trust::default(), Trust::PullRequest);
    }
}
