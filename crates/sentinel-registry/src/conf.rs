//! The `registries.conf` a pull reads, generated per scope.
//!
//! containers/image (Podman's pull path) resolves a named registry through `registries.conf`: a
//! `[[registry.mirror]]` sends the request to another endpoint first, and a mirror location may carry a
//! path prefix, which becomes the first components of the repository name the mirror is asked for. Each
//! scope therefore gets its own file, whose mirror location is `127.0.0.1:<port>/<scope token>/<host>`,
//! so the one listener can tell scopes apart without a credential of its own.
//!
//! The worker names the file with `CONTAINERS_REGISTRIES_CONF` instead of writing a host-wide
//! `/etc/containers/registries.conf`: the cache is one worker's, and a job's pull must not depend on
//! what an operator put in the host's copy. The empty `registries.conf.d` beside it keeps the host's
//! drop-in directory out of the resolution.

use std::path::{Path, PathBuf};

use crate::{Error, Registry, Result};

pub const CONF_DIR: &str = "conf";

const MAX_HOST_BYTES: usize = 253;

/// A registry host as a job's image reference may name it: lower-case letters, digits, dots and hyphens,
/// an optional port, or the bracketed IPv6 loopback.
pub fn check_host(host: &str) -> Result<()> {
    let (name, port) = match host.rsplit_once(':') {
        Some((name, port)) => (name, Some(port)),
        None => (host, None),
    };
    let ipv6 = name.starts_with('[') && name.ends_with(']');
    let named = !ipv6
        && !name.is_empty()
        && name.len() <= MAX_HOST_BYTES
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
        && name.split('.').all(|part| {
            !part.is_empty() && (part.len() < 64) && !part.starts_with('-') && !part.ends_with('-')
        });
    if !named && !(ipv6 && name == "[::1]") {
        return Err(Error::Config(format!(
            "registry host {host:?} is not a lower-case host name with an optional port"
        )));
    }
    if let Some(port) = port
        && (port.is_empty()
            || port.len() > 5
            || !port.bytes().all(|b| b.is_ascii_digit())
            || port.parse::<u16>().is_err())
    {
        return Err(Error::Config(format!(
            "registry host {host:?} has a port that is not a number"
        )));
    }
    Ok(())
}

pub(crate) fn write(
    root: &Path,
    token: &str,
    port: u16,
    registries: &[Registry],
) -> Result<PathBuf> {
    let dir = root.join(token);
    private_dir(&dir)?;
    private_dir(&dir.join("registries.conf.d"))?;
    let mut text = String::with_capacity(256 + 192 * registries.len());
    text.push_str(
        "# Sentinel's registry pull-through cache for one job scope: generated per pull, do not edit.\n\
         # A miss is fetched by the worker from the upstream registry; a hit is answered from local disk.\n\
         unqualified-search-registries = [\"docker.io\"]\n\n",
    );
    for registry in registries {
        text.push_str("[[registry]]\nprefix = \"");
        text.push_str(&registry.host);
        text.push_str("\"\nlocation = \"");
        text.push_str(&registry.host);
        text.push_str("\"\n");
        if crate::is_loopback_host(&registry.host) {
            // A loopback upstream is a local registry double or a private mirror: plain HTTP, so the
            // client must be told, exactly as for the cache's own loopback endpoint.
            text.push_str("insecure = true\n");
        }
        text.push_str("\n[[registry.mirror]]\nlocation = \"127.0.0.1:");
        text.push_str(&port.to_string());
        text.push('/');
        text.push_str(token);
        text.push('/');
        text.push_str(&registry.slug());
        text.push_str("\"\ninsecure = true\n\n");
    }
    let path = dir.join("registries.conf");
    write_private(&path, text.as_bytes())?;
    Ok(path)
}

fn private_dir(dir: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    Ok(())
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true).mode(0o600);
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_data()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_shapes_a_reference_may_name_are_accepted_and_nothing_else_is() {
        for host in [
            "docker.io",
            "ghcr.io",
            "registry.gitlab.com",
            "127.0.0.1:5000",
            "localhost",
            "quay.io",
        ] {
            assert!(check_host(host).is_ok(), "{host}");
        }
        for host in [
            "",
            "Docker.io",
            "docker io",
            "-docker.io",
            "docker-.io",
            "docker.io:",
            "docker.io:http",
            "10.0.0.1:99999",
            "../etc",
        ] {
            assert!(check_host(host).is_err(), "{host}");
        }
    }

    #[test]
    fn a_mirror_location_carries_the_scope_token_and_the_registry_host() {
        let root = tempfile::tempdir().unwrap();
        let path = write(
            root.path(),
            "0123456789abcdef0123456789abcdef",
            41873,
            &[
                Registry::canonical("docker.io"),
                Registry::canonical("ghcr.io"),
            ],
        )
        .unwrap();
        let text = std::fs::read_to_string(path).unwrap();
        assert!(
            text.contains(
                "location = \"127.0.0.1:41873/0123456789abcdef0123456789abcdef/docker.io\""
            )
        );
        assert!(
            text.contains(
                "location = \"127.0.0.1:41873/0123456789abcdef0123456789abcdef/ghcr.io\""
            )
        );
        assert!(text.contains("prefix = \"docker.io\""));
        assert!(text.contains("unqualified-search-registries = [\"docker.io\"]"));
    }
}
