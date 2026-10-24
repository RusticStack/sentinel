//! Nothing infers pull-request metadata from a ref: the adapter that produced the event must prove it.
use serde::{Deserialize, Serialize};

pub const MAX_REF_PATTERNS: usize = 32;
pub const MAX_REF_PATTERN_BYTES: usize = 256;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Triggers {
    pub push: Option<RefFilter>,
    pub pull_request: Option<RefFilter>,
    pub tag: Option<RefFilter>,
    pub manual: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefFilter {
    pub branches: Vec<String>,
    pub tags: Vec<String>,
}

impl RefFilter {
    pub fn accepts_branch(&self, branch: &str) -> bool {
        self.branches.is_empty() || self.branches.iter().any(|p| pattern_matches(p, branch))
    }

    pub fn accepts_tag(&self, tag: &str) -> bool {
        self.tags.is_empty() || self.tags.iter().any(|p| pattern_matches(p, tag))
    }
}

impl Triggers {
    pub fn is_empty(&self) -> bool {
        self.push.is_none() && self.pull_request.is_none() && self.tag.is_none() && !self.manual
    }

    pub fn admits(&self, event: &Event<'_>) -> bool {
        match event.kind {
            EventKind::Push => self
                .push
                .as_ref()
                .is_some_and(|f| event.branch().is_some_and(|b| f.accepts_branch(b))),
            EventKind::PullRequest => self
                .pull_request
                .as_ref()
                .is_some_and(|f| event.branch().is_some_and(|b| f.accepts_branch(b))),
            EventKind::Tag => self
                .tag
                .as_ref()
                .is_some_and(|f| event.tag_name().is_some_and(|t| f.accepts_tag(t))),
            EventKind::Manual => self.manual,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EventKind {
    Push = 0,
    PullRequest = 1,
    Tag = 2,
    Manual = 3,
}

impl EventKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Push => "push",
            Self::PullRequest => "pull_request",
            Self::Tag => "tag",
            Self::Manual => "manual",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "push" => Self::Push,
            "pull_request" => Self::PullRequest,
            "tag" => Self::Tag,
            "manual" => Self::Manual,
            _ => return None,
        })
    }
}

/// For pull requests this is the base branch, whose policy the change targets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Event<'a> {
    pub kind: EventKind,
    pub ref_name: &'a str,
}

impl<'a> Event<'a> {
    pub const fn push(ref_name: &'a str) -> Self {
        Self {
            kind: EventKind::Push,
            ref_name,
        }
    }

    pub const fn tag(ref_name: &'a str) -> Self {
        Self {
            kind: EventKind::Tag,
            ref_name,
        }
    }

    pub const fn pull_request(base_ref: &'a str) -> Self {
        Self {
            kind: EventKind::PullRequest,
            ref_name: base_ref,
        }
    }

    pub const fn manual() -> Self {
        Self {
            kind: EventKind::Manual,
            ref_name: "",
        }
    }

    fn branch(&self) -> Option<&'a str> {
        self.ref_name.strip_prefix("refs/heads/")
    }

    fn tag_name(&self) -> Option<&'a str> {
        self.ref_name.strip_prefix("refs/tags/")
    }
}

pub fn valid_pattern(pattern: &str) -> Result<(), &'static str> {
    if pattern.is_empty() || pattern.len() > MAX_REF_PATTERN_BYTES {
        return Err("must be 1-256 bytes");
    }
    if pattern.starts_with('/') || pattern.ends_with('/') || pattern.contains("//") {
        return Err("must be a relative ref path");
    }
    for segment in pattern.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err("must be a relative ref path");
        }
        if segment != "**"
            && (segment.contains("**")
                || segment
                    .bytes()
                    .any(|b| b <= 32 || b == 127 || b"~^:?[\\".contains(&b)))
        {
            return Err("must not contain `**` inside a segment or forbidden characters");
        }
    }
    Ok(())
}

pub fn pattern_matches(pattern: &str, value: &str) -> bool {
    let p: Vec<&str> = pattern.split('/').collect();
    let v: Vec<&str> = value.split('/').collect();
    let (mut pi, mut vi) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;
    while vi < v.len() {
        if pi < p.len() && p[pi] != "**" && crate::glob::segment(p[pi], v[vi]) {
            pi += 1;
            vi += 1;
        } else if pi < p.len() && p[pi] == "**" {
            star = Some((pi, vi));
            pi += 1;
        } else if let Some((sp, sv)) = star {
            pi = sp + 1;
            vi = sv + 1;
            star = Some((sp, sv + 1));
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == "**" {
        pi += 1;
    }
    pi == p.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push(branches: &[&str]) -> Triggers {
        Triggers {
            push: Some(RefFilter {
                branches: branches.iter().map(|s| s.to_string()).collect(),
                tags: Vec::new(),
            }),
            ..Triggers::default()
        }
    }

    #[test]
    fn kinds_and_refs_must_agree() {
        let t = push(&["main"]);
        assert!(t.admits(&Event::push("refs/heads/main")));
        assert!(!t.admits(&Event::push("refs/heads/dev")));
        assert!(!t.admits(&Event::push("refs/tags/v1")));
        assert!(!t.admits(&Event::tag("refs/heads/main")));
        assert!(!t.admits(&Event::manual()));
        let tags = Triggers {
            tag: Some(RefFilter {
                branches: Vec::new(),
                tags: vec!["v*".into()],
            }),
            ..Triggers::default()
        };
        assert!(tags.admits(&Event::tag("refs/tags/v1")));
        assert!(!tags.admits(&Event::tag("refs/tags/nightly")));
        assert!(Triggers::default().is_empty());
    }

    #[test]
    fn empty_filters_admit_every_ref_of_the_kind() {
        let t = Triggers {
            push: Some(RefFilter::default()),
            manual: true,
            ..Triggers::default()
        };
        assert!(t.admits(&Event::push("refs/heads/anything/at/all")));
        assert!(t.admits(&Event::manual()));
        assert!(!t.admits(&Event::tag("refs/tags/v1")));
    }

    #[test]
    fn pull_requests_are_admitted_by_their_base_branch_only() {
        let t = Triggers {
            pull_request: Some(RefFilter {
                branches: vec!["main".into(), "release/*".into()],
                tags: Vec::new(),
            }),
            ..Triggers::default()
        };
        assert!(t.admits(&Event::pull_request("refs/heads/main")));
        assert!(t.admits(&Event::pull_request("refs/heads/release/1.0")));
        assert!(!t.admits(&Event::pull_request("refs/heads/feature")));
        assert!(!t.admits(&Event::push("refs/heads/main")));
    }

    #[test]
    fn pattern_matching_is_anchored_and_bounded() {
        assert!(pattern_matches("main", "main"));
        assert!(pattern_matches("release/*", "release/1.0"));
        assert!(!pattern_matches("release/*", "release/1.0/x"));
        assert!(pattern_matches("**", "a/b/c"));
        assert!(pattern_matches("**", ""));
        assert!(pattern_matches("release/**", "release/1.0/x"));
        assert!(pattern_matches("release/**", "release"));
        assert!(pattern_matches("**/hotfix/*", "release/2/hotfix/one"));
        assert!(!pattern_matches("**/hotfix/*", "release/2/hotfix/one/two"));
        assert!(!pattern_matches("main", "maintenance"));
        let pattern = "**/".repeat(60) + "end";
        let value = "x/".repeat(80) + "end";
        assert!(pattern_matches(&pattern, &value));
    }

    #[test]
    fn patterns_are_validated() {
        for ok in ["main", "release/*", "**", "v*", "release/**", "a-b_c.d"] {
            assert!(valid_pattern(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "/main",
            "main/",
            "a//b",
            "a/**b",
            "has space",
            "has\tcontrol",
            "with~tilde",
            "with:colon",
            &"x".repeat(MAX_REF_PATTERN_BYTES + 1),
        ] {
            assert!(valid_pattern(bad).is_err(), "{bad}");
        }
    }
}
