//! The worker-only bootstrap script (Q11), rendered from `worker_bootstrap.sh`.
//!
//! The script carries the controller's public link fingerprint, its dial address and the SHA-256 pins of the release
//! artifacts, and nothing else: no enrollment secret, no Tailcat address, no credential of any kind. Every value is
//! validated against a conservative alphabet before it is spliced in as a single-quoted shell word, so a
//! configuration mistake cannot inject shell.

use std::{fmt::Write as _, net::SocketAddr, path::PathBuf};

use sentinel_link::tailcat::Address;

const TEMPLATE: &str = include_str!("worker_bootstrap.sh");
const BEGIN: &str = "# --- generated settings begin ---\n";
const END: &str = "# --- generated settings end ---\n";

/// Version of the settings contract between the controller and the script; the script refuses another.
pub const FORMAT: u32 = 1;
/// Longest value spliced into the script.
const MAX_VALUE: usize = 512;
/// The file holding the controller's Tailcat address is at most this long.
const MAX_ADDRESS_FILE: usize = 1024;
const ARCHES: [&str; 2] = ["x86_64", "aarch64"];

/// A release artifact pinned by digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pin {
    pub url: String,
    pub sha256: String,
}

/// The Tailcat helper the generated script installs: one pinned build per architecture.
#[derive(Clone, Debug, Default)]
pub struct TailcatRelease {
    pub version: String,
    pub x86_64: Option<Pin>,
    pub aarch64: Option<Pin>,
    /// Operator-owned DERP map, passed to the helper.
    pub derpmap_url: Option<String>,
    pub region: Option<String>,
}

/// What the controller's operator configures. [`WorkerBootstrap::new`] validates it.
#[derive(Clone, Debug)]
pub struct Settings {
    /// Where workers dial the controller's link listener for a direct TLS enrollment.
    pub controller: SocketAddr,
    /// The controller's link certificate fingerprint, 64 lower-case hex characters.
    pub fingerprint: String,
    /// The directory URL that holds the release archives.
    pub release_url: String,
    /// The release's `SHA256SUMS`, as `scripts/release/package.sh` writes it.
    pub release_sums: String,
    pub tailcat: Option<TailcatRelease>,
    /// The controller's `<data_dir>/tailcat/address` file; absent means no Tailcat enrollments.
    pub tailcat_address_file: Option<PathBuf>,
    /// The HTTPS base URL a worker redeems its enrollment at (`POST /api/v1/worker-enrollments/redeem`).
    /// Absent means the generated script keeps the older flow: the secret is presented with the worker's
    /// first link hello and, for Tailcat, authorized for the node key by an administrator.
    pub api_url: Option<String>,
}

/// Why a script cannot be rendered for an enrollment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unavailable {
    /// The enrollment is a Tailcat one but the controller has no Tailcat release pinned.
    NoTailcat,
}

#[derive(Debug)]
pub struct WorkerBootstrap {
    controller: SocketAddr,
    fingerprint: String,
    version: String,
    workers: [Option<Pin>; 2],
    tailcat: Option<TailcatRelease>,
    tailcat_address_file: Option<PathBuf>,
    api_url: Option<String>,
}

impl WorkerBootstrap {
    pub fn new(settings: Settings) -> Result<WorkerBootstrap, String> {
        let Settings {
            controller,
            fingerprint,
            release_url,
            release_sums,
            tailcat,
            tailcat_address_file,
            api_url,
        } = settings;
        if !is_hex64(&fingerprint) {
            return Err("fingerprint must be 64 lower-case hex characters".into());
        }
        let base = checked_url(&release_url, "release_url")?;
        let api_url = api_url
            .map(|url| checked_url(&url, "api_url").map(|url| url.trim_end_matches('/').to_owned()))
            .transpose()?;
        let base = base.trim_end_matches('/');
        let (version, sums) = release(&release_sums)?;
        let mut workers = [None, None];
        for (slot, arch) in workers.iter_mut().zip(ARCHES) {
            let name = format!("sentinel-{version}-{arch}-linux-worker.tar.gz");
            *slot = sums
                .iter()
                .find(|(_, file)| *file == name)
                .map(|(sha256, _)| Pin {
                    url: format!("{base}/{name}"),
                    sha256: sha256.clone(),
                });
        }
        if workers.iter().all(Option::is_none) {
            return Err("release_sums lists no worker archive".into());
        }
        if let Some(tailcat) = &tailcat {
            if tailcat.version.is_empty()
                || tailcat.version.len() > 32
                || !tailcat
                    .version
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'-'))
            {
                return Err("tailcat version must be 1-32 characters of [A-Za-z0-9._+-]".into());
            }
            for pin in [&tailcat.x86_64, &tailcat.aarch64].into_iter().flatten() {
                checked_url(&pin.url, "tailcat url")?;
                if !is_hex64(&pin.sha256) {
                    return Err("tailcat sha256 must be 64 lower-case hex characters".into());
                }
            }
            if tailcat.x86_64.is_none() && tailcat.aarch64.is_none() {
                return Err("[tailcat] pins no helper for any architecture".into());
            }
            if let Some(url) = &tailcat.derpmap_url {
                checked_url(url, "derpmap_url")?;
            }
            if let Some(region) = &tailcat.region
                && (region.is_empty()
                    || region.len() > 64
                    || !region
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')))
            {
                return Err("tailcat region must be 1-64 characters of [A-Za-z0-9._-]".into());
            }
        }
        Ok(WorkerBootstrap {
            controller,
            fingerprint,
            version,
            workers,
            tailcat,
            tailcat_address_file,
            api_url,
        })
    }

    /// Whether a Tailcat enrollment can be offered: a pinned helper and an address file are configured.
    pub fn tailcat_configured(&self) -> bool {
        self.tailcat.is_some() && self.tailcat_address_file.is_some()
    }

    /// The controller's Tailcat address as the worker must be given it; `None` while the controller
    /// has not written one yet. A credential: never log it.
    pub fn tailcat_address(&self) -> Option<Address> {
        let path = self.tailcat_address_file.as_ref()?;
        let bytes = read_bounded(path, MAX_ADDRESS_FILE)?;
        Address::parse(std::str::from_utf8(&bytes).ok()?)
    }

    pub fn release_version(&self) -> &str {
        &self.version
    }

    /// Whether workers redeem at the HTTPS endpoint (an `api_url` is configured).
    pub fn redeems_over_https(&self) -> bool {
        self.api_url.is_some()
    }

    /// Where a direct TLS worker dials the link listener.
    pub fn controller(&self) -> SocketAddr {
        self.controller
    }

    /// The controller's public link certificate fingerprint, 64 lower-case hex characters.
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// The script for one transport: identical for every enrollment of that transport, and free of secrets.
    pub fn render(&self, tailcat: bool) -> Result<String, Unavailable> {
        if tailcat && self.tailcat.is_none() {
            return Err(Unavailable::NoTailcat);
        }
        let (Some(begin), Some(end)) = (TEMPLATE.find(BEGIN), TEMPLATE.find(END)) else {
            unreachable!("the template is committed with its settings markers");
        };
        let mut script = String::with_capacity(TEMPLATE.len() + 1024);
        script.push_str(&TEMPLATE[..begin + BEGIN.len()]);
        let mut put = |name: &str, value: &str| {
            debug_assert!(
                is_word(value),
                "{name} is validated before it is spliced in"
            );
            let _ = writeln!(script, "{name}='{value}'");
        };
        let [x86, arm] = &self.workers;
        let helper = self.tailcat.as_ref().filter(|_| tailcat);
        put("BOOTSTRAP_FORMAT", &FORMAT.to_string());
        put("TRANSPORT", if tailcat { "tailcat" } else { "direct" });
        put("CONTROLLER_ADDR", &self.controller.to_string());
        put("CONTROLLER_FINGERPRINT", &self.fingerprint);
        put("API_URL", self.api_url.as_deref().unwrap_or(""));
        put("RELEASE_VERSION", &self.version);
        put("WORKER_URL_X86_64", url(x86));
        put("WORKER_SHA256_X86_64", sum(x86));
        put("WORKER_URL_AARCH64", url(arm));
        put("WORKER_SHA256_AARCH64", sum(arm));
        put("TAILCAT_VERSION", helper.map_or("", |t| t.version.as_str()));
        put("TAILCAT_URL_X86_64", helper.map_or("", |t| url(&t.x86_64)));
        put(
            "TAILCAT_SHA256_X86_64",
            helper.map_or("", |t| sum(&t.x86_64)),
        );
        put(
            "TAILCAT_URL_AARCH64",
            helper.map_or("", |t| url(&t.aarch64)),
        );
        put(
            "TAILCAT_SHA256_AARCH64",
            helper.map_or("", |t| sum(&t.aarch64)),
        );
        put(
            "TAILCAT_DERPMAP_URL",
            helper.and_then(|t| t.derpmap_url.as_deref()).unwrap_or(""),
        );
        put(
            "TAILCAT_REGION",
            helper.and_then(|t| t.region.as_deref()).unwrap_or(""),
        );
        script.push_str(&TEMPLATE[end..]);
        Ok(script)
    }
}

fn url(pin: &Option<Pin>) -> &str {
    pin.as_ref().map_or("", |p| p.url.as_str())
}

fn sum(pin: &Option<Pin>) -> &str {
    pin.as_ref().map_or("", |p| p.sha256.as_str())
}

fn read_bounded(path: &std::path::Path, max: usize) -> Option<Vec<u8>> {
    use std::io::Read as _;
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .ok()?
        .take(max as u64 + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    (bytes.len() <= max).then_some(bytes)
}

/// A shell word that is safe inside single quotes and inside a TOML basic string.
fn is_word(value: &str) -> bool {
    value.len() <= MAX_VALUE
        && value
            .bytes()
            .all(|b| (0x21..=0x7e).contains(&b) && !matches!(b, b'\'' | b'"' | b'\\' | b'`'))
}

fn is_hex64(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// `https://`, or `http://` for a loopback host only; no user information, query or fragment, so a URL
/// never carries a credential.
fn checked_url(text: &str, what: &str) -> Result<String, String> {
    if !is_word(text) {
        return Err(format!("{what} holds a character a URL here may not"));
    }
    let url = url::Url::parse(text).map_err(|_| format!("{what} is not an absolute URL"))?;
    let loopback = match url.host() {
        Some(url::Host::Domain(name)) => name == "localhost",
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => return Err(format!("{what} has no host")),
    };
    let scheme_ok = url.scheme() == "https" || (url.scheme() == "http" && loopback);
    if !scheme_ok {
        return Err(format!(
            "{what} must be an https:// URL (http:// only for a loopback host)"
        ));
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(format!(
            "{what} must not carry user information, a query or a fragment: credentials never go in URLs"
        ));
    }
    Ok(text.to_owned())
}

/// The worker archives of a `SHA256SUMS` file: `(sha256, file name)` pairs and the one release version they name.
fn release(sums: &str) -> Result<(String, Vec<(String, String)>), String> {
    let mut entries = Vec::new();
    let mut version: Option<String> = None;
    for line in sums.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((digest, file)) = line.split_once(char::is_whitespace) else {
            return Err("release_sums has a line that is not '<sha256>  <file>'".into());
        };
        let file = file.trim_start().trim_start_matches('*');
        if !is_hex64(digest) {
            return Err(
                "release_sums has a digest that is not 64 lower-case hex characters".into(),
            );
        }
        let Some(rest) = file
            .strip_prefix("sentinel-")
            .and_then(|r| r.strip_suffix("-linux-worker.tar.gz"))
        else {
            continue;
        };
        let Some((found, arch)) = rest.rsplit_once('-') else {
            continue;
        };
        if !ARCHES.contains(&arch) {
            continue;
        }
        if found.is_empty()
            || found.len() > 64
            || !found
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'~' | b'-'))
        {
            return Err("release_sums names a worker archive with an unusable version".into());
        }
        match &version {
            None => version = Some(found.to_owned()),
            Some(first) if first == found => {}
            Some(_) => {
                return Err("release_sums mixes worker archives of different versions".into());
            }
        }
        entries.push((digest.to_owned(), file.to_owned()));
    }
    let version = version.ok_or("release_sums lists no worker archive")?;
    Ok((version, entries))
}

#[cfg(test)]
mod tests {
    use super::*;

    const X86: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const ARM: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const TC: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const FP: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

    fn sums() -> String {
        format!(
            "{X86}  sentinel-0.1.0-x86_64-linux-worker.tar.gz\n\
             {ARM}  sentinel-0.1.0-aarch64-linux-worker.tar.gz\n\
             {TC}  sentinel-0.1.0-x86_64-linux-server.tar.gz\n"
        )
    }

    fn settings() -> Settings {
        Settings {
            controller: "10.0.0.5:7443".parse().unwrap(),
            fingerprint: FP.into(),
            release_url: "https://releases.example.test/sentinel/0.1.0/".into(),
            release_sums: sums(),
            tailcat: Some(TailcatRelease {
                version: "0.6.0".into(),
                x86_64: Some(Pin {
                    url: "https://releases.example.test/tailcat/0.6.0/tailcat-linux-amd64".into(),
                    sha256: TC.into(),
                }),
                aarch64: None,
                derpmap_url: Some("https://derp.example.test/derp.json".into()),
                region: Some("derp.example.test".into()),
            }),
            tailcat_address_file: None,
            api_url: Some("https://ci.example.test/".into()),
        }
    }

    fn value<'a>(script: &'a str, name: &str) -> &'a str {
        let prefix = format!("{name}='");
        script
            .lines()
            .find_map(|l| l.strip_prefix(&prefix)?.strip_suffix('\''))
            .unwrap_or_else(|| panic!("{name} missing"))
    }

    #[test]
    fn the_script_pins_the_release_and_leaves_no_slot_unvalidated() {
        let script = WorkerBootstrap::new(settings())
            .unwrap()
            .render(true)
            .unwrap();
        assert!(script.starts_with("#!/bin/sh\n"));
        assert_eq!(value(&script, "BOOTSTRAP_FORMAT"), "1");
        assert_eq!(value(&script, "TRANSPORT"), "tailcat");
        assert_eq!(value(&script, "RELEASE_VERSION"), "0.1.0");
        assert_eq!(value(&script, "CONTROLLER_ADDR"), "10.0.0.5:7443");
        assert_eq!(value(&script, "CONTROLLER_FINGERPRINT"), FP);
        assert_eq!(value(&script, "WORKER_SHA256_X86_64"), X86);
        assert_eq!(
            value(&script, "WORKER_URL_AARCH64"),
            "https://releases.example.test/sentinel/0.1.0/sentinel-0.1.0-aarch64-linux-worker.tar.gz"
        );
        assert_eq!(value(&script, "TAILCAT_SHA256_X86_64"), TC);
        assert_eq!(value(&script, "TAILCAT_URL_AARCH64"), "");
        assert_eq!(value(&script, "TAILCAT_REGION"), "derp.example.test");
    }

    #[test]
    fn a_direct_script_carries_no_tailcat_pin_and_the_template_body_is_unchanged() {
        let script = WorkerBootstrap::new(settings())
            .unwrap()
            .render(false)
            .unwrap();
        assert_eq!(value(&script, "TRANSPORT"), "direct");
        for name in [
            "TAILCAT_VERSION",
            "TAILCAT_URL_X86_64",
            "TAILCAT_SHA256_X86_64",
            "TAILCAT_DERPMAP_URL",
            "TAILCAT_REGION",
        ] {
            assert_eq!(value(&script, name), "", "{name}");
        }
        let body = |text: &str| text[text.find(END).unwrap()..].to_owned();
        assert_eq!(body(&script), body(TEMPLATE));
    }

    #[test]
    fn a_tailcat_script_needs_a_pinned_helper() {
        let mut direct_only = settings();
        direct_only.tailcat = None;
        let bootstrap = WorkerBootstrap::new(direct_only).unwrap();
        assert_eq!(bootstrap.render(true).unwrap_err(), Unavailable::NoTailcat);
        assert!(bootstrap.render(false).is_ok());
        assert!(!bootstrap.tailcat_configured());
    }

    #[test]
    fn a_value_that_could_break_out_of_a_shell_word_is_refused() {
        for bad in [
            "https://releases.example.test/a'b",
            "https://releases.example.test/a\"b",
            "https://releases.example.test/a b",
            "https://releases.example.test/a\\b",
            "https://releases.example.test/`id`",
        ] {
            let mut s = settings();
            s.release_url = bad.into();
            assert!(WorkerBootstrap::new(s).is_err(), "{bad}");
        }
        let mut s = settings();
        s.release_sums = format!("{X86}  sentinel-0.1.0'x-x86_64-linux-worker.tar.gz\n");
        assert!(WorkerBootstrap::new(s).is_err());
    }

    #[test]
    fn urls_never_carry_credentials_and_plain_http_is_loopback_only() {
        for bad in [
            "https://user:pw@releases.example.test/x",
            "https://token@releases.example.test/x",
            "https://releases.example.test/x?token=abc",
            "https://releases.example.test/x#frag",
            "http://releases.example.test/x",
            "ftp://releases.example.test/x",
            "releases.example.test/x",
        ] {
            let mut s = settings();
            s.release_url = bad.into();
            assert!(WorkerBootstrap::new(s).is_err(), "{bad}");
        }
        for good in [
            "http://127.0.0.1:8080/r",
            "http://localhost/r",
            "https://example.test/r",
        ] {
            let mut s = settings();
            s.release_url = good.into();
            assert!(WorkerBootstrap::new(s).is_ok(), "{good}");
        }
    }

    #[test]
    fn digests_and_fingerprints_must_be_lower_case_hex() {
        let mut s = settings();
        s.fingerprint = FP.to_uppercase();
        assert!(WorkerBootstrap::new(s).is_err());
        let mut s = settings();
        s.release_sums = format!(
            "{}  sentinel-0.1.0-x86_64-linux-worker.tar.gz\n",
            &X86[..63]
        );
        assert!(WorkerBootstrap::new(s).is_err());
        let mut s = settings();
        s.tailcat.as_mut().unwrap().x86_64.as_mut().unwrap().sha256 = TC.to_uppercase();
        assert!(WorkerBootstrap::new(s).is_err());
    }

    #[test]
    fn a_release_must_be_one_version_with_a_worker_archive() {
        let mut s = settings();
        s.release_sums = format!(
            "{X86}  sentinel-0.1.0-x86_64-linux-worker.tar.gz\n\
             {ARM}  sentinel-0.2.0-aarch64-linux-worker.tar.gz\n"
        );
        assert!(WorkerBootstrap::new(s).is_err());
        let mut s = settings();
        s.release_sums = format!("{TC}  sentinel-0.1.0-x86_64-linux-server.tar.gz\n");
        assert!(WorkerBootstrap::new(s).is_err());
        let mut s = settings();
        s.release_sums = format!("{X86} *sentinel-0.1.0-rc.1-x86_64-linux-worker.tar.gz\n");
        let bootstrap = WorkerBootstrap::new(s).unwrap();
        assert_eq!(bootstrap.release_version(), "0.1.0-rc.1");
        let script = bootstrap.render(false).unwrap();
        assert_eq!(value(&script, "WORKER_URL_AARCH64"), "");
        assert_eq!(value(&script, "WORKER_SHA256_X86_64"), X86);
    }

    #[test]
    fn the_api_url_is_pinned_without_credentials_and_may_be_left_out() {
        let script = WorkerBootstrap::new(settings())
            .unwrap()
            .render(true)
            .unwrap();
        assert_eq!(value(&script, "API_URL"), "https://ci.example.test");
        let mut older = settings();
        older.api_url = None;
        let older = WorkerBootstrap::new(older).unwrap();
        assert!(!older.redeems_over_https());
        assert_eq!(value(&older.render(true).unwrap(), "API_URL"), "");
        for bad in [
            "http://ci.example.test",
            "https://user:pw@ci.example.test",
            "https://ci.example.test/?token=x",
            "https://ci.example.test/#frag",
            "ci.example.test",
        ] {
            let mut s = settings();
            s.api_url = Some(bad.into());
            assert!(WorkerBootstrap::new(s).is_err(), "{bad}");
        }
        let mut loopback = settings();
        loopback.api_url = Some("http://127.0.0.1:8080".into());
        assert!(WorkerBootstrap::new(loopback).is_ok());
    }

    #[test]
    fn the_settings_block_of_the_template_is_empty_and_marked_once() {
        assert_eq!(TEMPLATE.matches(BEGIN).count(), 1);
        assert_eq!(TEMPLATE.matches(END).count(), 1);
        let block =
            &TEMPLATE[TEMPLATE.find(BEGIN).unwrap() + BEGIN.len()..TEMPLATE.find(END).unwrap()];
        assert!(block.lines().all(|l| l.ends_with("=''")), "{block}");
    }
}
