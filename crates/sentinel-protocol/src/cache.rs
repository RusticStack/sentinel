use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum Class {
    Downloads = 0,
    #[default]
    Dependencies = 1,
    Compiler = 2,
}

impl Class {
    pub const ALL: [Class; 3] = [Self::Downloads, Self::Dependencies, Self::Compiler];

    pub const fn to_u8(self) -> u8 {
        self as u8
    }
    pub const fn from_u8(code: u8) -> Option<Class> {
        match code {
            0 => Some(Self::Downloads),
            1 => Some(Self::Dependencies),
            2 => Some(Self::Compiler),
            _ => None,
        }
    }
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Downloads => "downloads",
            Self::Dependencies => "dependencies",
            Self::Compiler => "compiler",
        }
    }
    pub fn of_name(name: &str) -> Option<Class> {
        Self::ALL.iter().copied().find(|c| c.as_str() == name)
    }
}

impl std::fmt::Display for Class {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Each class reads and writes only its own scope, so an untrusted class cannot
/// plant state that a protected build restores.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum Trust {
    Protected = 0,
    #[default]
    PullRequest = 1,
    /// Protocol 8; an older worker is sent `PullRequest`.
    Unprotected = 2,
}

impl Trust {
    pub const ALL: [Trust; 3] = [Self::Protected, Self::PullRequest, Self::Unprotected];

    pub fn derive(event: &str, verified_intake: bool, protected_ref: bool) -> Trust {
        match event {
            "pull_request" => Trust::PullRequest,
            "push" | "tag" if verified_intake && protected_ref => Trust::Protected,
            _ => Trust::Unprotected,
        }
    }

    pub const fn for_protocol(self, protocol: u16) -> Trust {
        match self {
            Self::Unprotected if protocol < 8 => Self::PullRequest,
            other => other,
        }
    }

    pub const fn admits(self, requested: Trust) -> bool {
        matches!(
            (self, requested),
            (Self::Protected, Self::Protected)
                | (Self::PullRequest, Self::PullRequest)
                | (Self::Unprotected, Self::Unprotected | Self::PullRequest)
        )
    }

    pub const fn to_u8(self) -> u8 {
        self as u8
    }
    pub const fn from_u8(code: u8) -> Option<Trust> {
        match code {
            0 => Some(Self::Protected),
            1 => Some(Self::PullRequest),
            2 => Some(Self::Unprotected),
            _ => None,
        }
    }
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Protected => "protected",
            Self::PullRequest => "pull_request",
            Self::Unprotected => "unprotected",
        }
    }
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
