//! Credentials are ephemeral checkout inputs, never part of a persisted run specification.

use serde::{Deserialize, Serialize};

pub const MAX_SOURCE_BYTES: usize = 48 * 1024;
pub const MAX_SECRET_BYTES: usize = 16 * 1024;
pub const MAX_REFS: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Binding {
    pub remote: String,
    pub allowed_refs: Vec<String>,
    pub pipeline_path: String,
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
        assert!(valid_ref_pattern("refs/heads/main"), "ref");
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
            && self.allowed_refs.iter().all(|r| valid_ref_pattern(r))
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
        valid_ref_pattern(reference)
            && !reference.contains('*')
            && self.allowed_refs.iter().any(|r| ref_matches(r, reference))
    }
}

pub fn valid_ref_pattern(r: &str) -> bool {
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

pub fn ref_matches(pattern: &str, reference: &str) -> bool {
    pattern
        .strip_suffix('*')
        .map_or(pattern == reference, |prefix| reference.starts_with(prefix))
}

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
    pub fn well_formed(&self) -> bool {
        self.version > 0
            && self.binding.validate()
            && self.credential.valid_for(&self.binding.remote)
    }

    pub fn validate(&self, now_ms: i64) -> bool {
        self.expires_ms > now_ms && self.well_formed()
    }

    // expires_ms is a controller wall-clock instant; the holder re-bases it on its own clock.
    #[must_use]
    pub fn rebased(mut self, now_ms: i64, window_ms: i64) -> Self {
        self.expires_ms = now_ms.saturating_add(window_ms);
        self
    }
}

pub const MANUAL_DESTINATIONS_ENV: &str = "SENTINEL_MANUAL_DESTINATIONS";

fn listed_manual_destinations() -> &'static [String] {
    static LIST: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();
    LIST.get_or_init(|| {
        std::env::var(MANUAL_DESTINATIONS_ENV)
            .map(|v| {
                v.split(',')
                    .map(str::trim)
                    .filter(|a| !a.is_empty())
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default()
    })
}

pub fn manual_destination_listed(remote_url: &str) -> bool {
    remote(remote_url)
        .is_some_and(|authority| listed_manual_destinations().iter().any(|a| a == authority))
}

pub fn https_host_port(remote_url: &str) -> Option<(&str, u16)> {
    let authority = remote(remote_url)?.strip_prefix("https://")?;
    Some(match authority.split_once(':') {
        Some((host, port)) => (host, port.parse().ok()?),
        None => (authority, 443),
    })
}

pub fn public_dns_name(host: &str) -> bool {
    const PRIVATE_TLDS: [&str; 11] = [
        "localhost",
        "local",
        "localdomain",
        "internal",
        "lan",
        "home",
        "corp",
        "intranet",
        "private",
        "arpa",
        "invalid",
    ];
    let host = host.strip_suffix('.').unwrap_or(host);
    let mut labels = host.rsplit('.');
    let Some(tld) = labels.next() else {
        return false;
    };
    let tld_ok = (tld.len() >= 2 && tld.bytes().all(|b| b.is_ascii_lowercase()))
        || (tld.starts_with("xn--") && tld.len() > 4);
    let rest: Vec<&str> = labels.collect();
    tld_ok && !PRIVATE_TLDS.contains(&tld) && !rest.is_empty() && rest.iter().all(|l| !l.is_empty())
}

pub fn manual_destination_allowed(remote_url: &str) -> bool {
    https_host_port(remote_url).is_some_and(|(host, _)| public_dns_name(host))
        || (remote_url.starts_with("https://") && manual_destination_listed(remote_url))
}

#[cfg(test)]
mod destination_tests {
    use super::*;

    #[test]
    fn public_names_pass_and_internal_forms_do_not() {
        for ok in [
            "git.example.com",
            "github.com",
            "a-b.example.org",
            "x.xn--p1ai",
        ] {
            assert!(public_dns_name(ok), "{ok}");
        }
        for bad in [
            "localhost",
            "intranet",
            "127.0.0.1",
            "169.254.169.254",
            "2130706433",
            "0x7f.1",
            "0x7f.0.0.1",
            "10.0.0.1",
            "printer.local",
            "svc.cluster.internal",
            "a..com",
            "x.localhost",
            "",
        ] {
            assert!(!public_dns_name(bad), "{bad}");
        }
    }

    #[test]
    fn manual_destinations_are_https_with_a_public_name() {
        assert!(manual_destination_allowed(
            "https://git.example.com/team/repo.git"
        ));
        assert!(manual_destination_allowed("https://git.example.com:8443/r"));
        assert!(!manual_destination_allowed(
            "https://169.254.169.254/latest"
        ));
        assert!(!manual_destination_allowed(
            "https://metadata/computeMetadata"
        ));
        assert!(!manual_destination_allowed("https://127.0.0.1:8443/repo"));
        assert!(!manual_destination_allowed(
            "ssh://git@git.example.com/repo"
        ));
    }

    #[test]
    fn a_rebased_access_is_live_by_the_holders_clock_alone() {
        let access = Access {
            binding: Binding {
                remote: "https://git.example.com/r".into(),
                allowed_refs: vec!["refs/heads/main".into()],
                pipeline_path: ".sentinel.yml".into(),
                trust: String::new(),
            },
            version: 1,
            expires_ms: 1,
            credential: Credential::Public,
        };
        assert!(access.well_formed());
        assert!(!access.validate(1_000));
        let rebased = access.rebased(1_000, 5_000);
        assert!(rebased.validate(5_999));
        assert!(!rebased.validate(6_000));
    }
}
