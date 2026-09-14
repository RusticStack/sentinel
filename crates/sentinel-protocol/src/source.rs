//! Bounded source-access contract. Credentials are ephemeral checkout inputs,
//! never part of a persisted run specification.
use serde::{Deserialize, Serialize};

pub const MAX_SOURCE_BYTES: usize = 48 * 1024;
pub const MAX_SECRET_BYTES: usize = 16 * 1024;
pub const MAX_REFS: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Binding {
    pub remote: String,
    pub allowed_refs: Vec<String>,
    pub pipeline_path: String,
    /// PEM trust roots for HTTPS, or OpenSSH known_hosts for SSH.
    pub trust: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_binding_with_pinned_trust_validates() {
        let b = Binding {
            remote: "ssh://root@127.0.0.1:23271/tmp/sentinel-ssh-8271/origin.git".into(),
            allowed_refs: vec!["refs/heads/main".into()],
            pipeline_path: ".sentinel.yml".into(),
            trust: "127.0.0.1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n".into(),
        };
        assert!(remote(&b.remote).is_some(), "remote");
        assert!(valid_ref("refs/heads/main"), "ref");
        assert!(b.validate(), "validate");
    }

    #[test]
    fn only_explicit_credential_free_network_remotes_are_accepted() {
        for value in [
            "file:///x",
            "/tmp/repo",
            "git@host:path",
            "ext::sh -c hi",
            "https://user:password@host/repo",
            "https://host/repo?token=x",
            "https://host/repo#x",
            "https://host/%2e%2e/repo",
            "https://host:0/repo",
            "ssh://-oProxyCommand@host/repo",
            "https://host/repo\n",
        ] {
            assert!(remote(value).is_none(), "{value}");
        }
        assert_eq!(
            remote("ssh://git@forge.example:2222/team/repo.git"),
            Some("ssh://git@forge.example:2222")
        );
        assert_eq!(
            remote("https://forge.example:8443/team/repo.git"),
            Some("https://forge.example:8443")
        );
    }
    #[test]
    fn refs_paths_trust_and_expiry_are_bounded() {
        let mut b = Binding {
            remote: "https://forge.example/r.git".into(),
            allowed_refs: vec!["refs/heads/main".into(), "refs/tags/v*".into()],
            pipeline_path: "ci/.sentinel.yml".into(),
            trust: String::new(),
        };
        assert!(b.validate());
        assert!(b.allows("refs/tags/v1"));
        assert!(!b.allows("refs/tags/v*"));
        assert!(!b.allows("refs/heads/other"));
        for path in ["../x", "/x", "a//x", "a/./x", "a\\x", "a\nx"] {
            b.pipeline_path = path.into();
            assert!(!b.validate());
        }
        b.pipeline_path = ".sentinel.yml".into();
        b.remote = "ssh://git@forge.example/r.git".into();
        assert!(!b.validate());
        b.trust = "forge.example ssh-ed25519 AAAA".into();
        assert!(b.validate());
        let access = Access {
            binding: b,
            credential: Credential::Ssh {
                private_key: "test-key".into(),
            },
            version: 1,
            expires_ms: 100,
        };
        assert!(access.validate(99));
        assert!(!access.validate(100));
    }
}

impl Binding {
    pub fn validate(&self) -> bool {
        remote(&self.remote).is_some()
            && !self.allowed_refs.is_empty()
            && self.allowed_refs.len() <= MAX_REFS
            && self.allowed_refs.iter().all(|r| valid_ref(r))
            && !self.pipeline_path.is_empty()
            && self.pipeline_path.len() <= 1024
            && !self.pipeline_path.starts_with('/')
            && self
                .pipeline_path
                .split('/')
                .all(|p| !p.is_empty() && p != "." && p != "..")
            && !self
                .pipeline_path
                .bytes()
                .any(|b| b < 32 || b == 127 || b == b'\\')
            && self.trust.len() <= MAX_SECRET_BYTES
            && !self.trust.contains('\0')
            && (!self.remote.starts_with("ssh://") || !self.trust.is_empty())
    }

    pub fn allows(&self, reference: &str) -> bool {
        valid_ref(reference)
            && !reference.contains('*')
            && self.allowed_refs.iter().any(|r| {
                r.strip_suffix('*')
                    .map_or(r == reference, |prefix| reference.starts_with(prefix))
            })
    }
}

fn valid_ref(r: &str) -> bool {
    (r.starts_with("refs/heads/") || r.starts_with("refs/tags/"))
        && r.len() <= 1024
        && !r.ends_with('/')
        && !r.ends_with('.')
        && !r.contains("..")
        && !r.contains("@{")
        && !r.contains("//")
        && r.split('/')
            .all(|s| !s.starts_with('.') && !s.ends_with(".lock"))
        && !r.trim_end_matches('*').contains('*')
        && !r
            .bytes()
            .any(|b| b <= 32 || b == 127 || b"~^:?\\[".contains(&b))
}

/// Exact deployment-allowlist key: transport plus hostname and explicit port.
/// No passwords, query, fragment, scp syntax, local paths or remote helpers.
pub fn remote(value: &str) -> Option<&str> {
    if value.len() > 2048
        || value
            .bytes()
            .any(|b| b <= 32 || b >= 127 || b"\\?#%".contains(&b))
    {
        return None;
    }
    let (scheme, rest) = value.split_once("://")?;
    if !matches!(scheme, "https" | "ssh") {
        return None;
    }
    let (authority, path) = rest.split_once('/')?;
    if path.is_empty()
        || path
            .split('/')
            .any(|s| s.is_empty() || s == "." || s == "..")
    {
        return None;
    }
    let host = if scheme == "ssh" {
        let (user, host) = authority.split_once('@')?;
        if user.is_empty()
            || user.starts_with('-')
            || !user
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
        {
            return None;
        }
        host
    } else {
        authority
    };
    let (hostname, port) = host
        .split_once(':')
        .map_or((host, None), |(h, p)| (h, Some(p)));
    if hostname.is_empty()
        || hostname.starts_with('-')
        || hostname.ends_with('-')
        || !hostname
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b".-".contains(&b))
        || port.is_some_and(|p| p.parse::<u16>().ok().is_none_or(|n| n == 0))
    {
        return None;
    }
    // Includes the SSH username, deliberately: allowlists are exact authorities.
    Some(&value[..scheme.len() + 3 + authority.len()])
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Credential {
    Public,
    Https { username: String, secret: String },
    Ssh { private_key: String },
}

impl core::fmt::Debug for Credential {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Credential(redacted)")
    }
}

impl Credential {
    pub fn valid_for(&self, remote: &str) -> bool {
        let valid = |s: &str| !s.is_empty() && s.len() <= MAX_SECRET_BYTES && !s.contains('\0');
        match self {
            Self::Public => remote.starts_with("https://"),
            Self::Https { username, secret } => {
                remote.starts_with("https://")
                    && valid(secret)
                    && username.len() <= 256
                    && valid(username)
                    && !username.contains(['\r', '\n'])
                    && !secret.contains(['\r', '\n'])
            }
            Self::Ssh { private_key } => remote.starts_with("ssh://") && valid(private_key),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Access {
    pub binding: Binding,
    pub version: u64,
    pub expires_ms: i64,
    pub credential: Credential,
}

impl Access {
    pub fn validate(&self, now_ms: i64) -> bool {
        self.version > 0
            && self.expires_ms > now_ms
            && self.binding.validate()
            && self.credential.valid_for(&self.binding.remote)
    }
}
