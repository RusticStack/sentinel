//! The optional external S3 blob adapter (R02): a small, synchronous client
//! for the S3 operations Sentinel's storage needs, signed with Signature V4
//! over the same rustls/ring stack as the rest of the controller. No SDK,
//! no async runtime, no MinIO dependency — any endpoint that speaks the S3
//! API: AWS, Cloudflare R2, Backblaze B2, MinIO, Garage, SeaweedFS, Ceph.
//!
//! Bounded on every axis the remote controls: connect and per-read timeouts,
//! response header size, response body size for everything but an object
//! read (which is bounded by its own `Content-Length`), no redirects. A
//! credential appears in one header per request and nowhere else — not in
//! a URL, an error or `Debug` output.

pub mod client;
pub mod sigv4;
pub mod xml;

pub use client::{Client, Head, MultipartUpload, ObjectPage, Part};

use std::{fmt, path::PathBuf, time::Duration};

/// What went wrong, classified for the caller's retry decision.
#[derive(Debug)]
pub enum Error {
    /// The configuration cannot work (bad endpoint, unreadable CA or
    /// credentials file). Not retried.
    Config(String),
    /// No such key, bucket or upload.
    NotFound(String),
    /// The service refused the credentials or the request (4xx other than
    /// not-found and throttling). Retrying the same request will not help.
    Refused { status: u16, code: String },
    /// Worth retrying later: a transport failure, a timeout, a 5xx, a
    /// `SlowDown`/throttling answer.
    Transient(String),
    /// The service answered something this client cannot use.
    Protocol(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Config(why) => write!(f, "S3 configuration: {why}"),
            Error::NotFound(what) => write!(f, "S3: not found: {what}"),
            Error::Refused { status, code } => write!(f, "S3 refused the request: {status} {code}"),
            Error::Transient(why) => write!(f, "S3 unavailable: {why}"),
            Error::Protocol(why) => write!(f, "S3 protocol: {why}"),
        }
    }
}

impl std::error::Error for Error {}

impl Error {
    /// Whether a later retry of the same request may succeed.
    pub fn is_transient(&self) -> bool {
        matches!(self, Error::Transient(_))
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// The access key, secret and optional session token. The secret is wiped
/// on drop and never printed.
pub struct Credentials {
    pub access_key_id: String,
    secret: zeroize::Zeroizing<Vec<u8>>,
    pub session_token: Option<String>,
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field("access_key_id", &self.access_key_id)
            .field("secret", &"<redacted>")
            .field(
                "session_token",
                &self.session_token.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl Credentials {
    pub fn new(
        access_key_id: String,
        secret: Vec<u8>,
        session_token: Option<String>,
    ) -> Result<Self> {
        let printable = |s: &[u8]| {
            !s.is_empty() && s.len() <= 1024 && s.iter().all(|b| (0x21..0x7f).contains(b))
        };
        if !printable(access_key_id.as_bytes())
            || !printable(&secret)
            || session_token
                .as_deref()
                .is_some_and(|t| t.len() > 4096 || !t.bytes().all(|b| (0x21..0x7f).contains(&b)))
        {
            return Err(Error::Config("credentials must be printable ASCII".into()));
        }
        Ok(Credentials {
            access_key_id,
            secret: zeroize::Zeroizing::new(secret),
            session_token,
        })
    }

    /// Read `access_key_id = …`, `secret_access_key = …` and optionally
    /// `session_token = …` lines from an owner-only file of at most 8 KiB.
    /// The contents are never echoed in an error.
    pub fn from_file(path: &std::path::Path) -> Result<Self> {
        let refuse = |why: &str| Error::Config(format!("{}: {why}", path.display()));
        let meta = std::fs::symlink_metadata(path).map_err(|_| refuse("cannot read"))?;
        if !meta.is_file() || meta.len() > 8 * 1024 {
            return Err(refuse("must be a regular file of at most 8 KiB"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if meta.permissions().mode() & 0o077 != 0 {
                return Err(refuse("must be readable by its owner only"));
            }
        }
        let text = zeroize::Zeroizing::new(std::fs::read(path).map_err(|_| refuse("cannot read"))?);
        let text = std::str::from_utf8(&text).map_err(|_| refuse("must be UTF-8"))?;
        let (mut key, mut secret, mut token) = (None, None, None);
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (name, value) = line
                .split_once('=')
                .ok_or_else(|| refuse("lines must be `name = value`"))?;
            let value = value.trim().trim_matches('"').to_owned();
            match name.trim() {
                "access_key_id" => key = Some(value),
                "secret_access_key" => secret = Some(value.into_bytes()),
                "session_token" => token = Some(value),
                _ => {
                    return Err(refuse(
                        "unknown setting (access_key_id, secret_access_key, session_token)",
                    ));
                }
            }
        }
        match (key, secret) {
            (Some(key), Some(secret)) => Credentials::new(key, secret, token),
            _ => Err(refuse("needs access_key_id and secret_access_key")),
        }
    }

    pub(crate) fn secret(&self) -> &[u8] {
        &self.secret
    }
}

/// Where the bucket is and how to reach it.
#[derive(Debug)]
pub struct Config {
    /// `https://s3.eu-central-1.amazonaws.com`, `http://127.0.0.1:9000`, …
    /// Scheme, host and optional port only.
    pub endpoint: String,
    pub region: String,
    pub bucket: String,
    /// Every key starts with this (`sentinel/prod/`); empty for the bucket
    /// root. Must end in `/` when set.
    pub prefix: String,
    /// `https://endpoint/bucket/key` instead of `https://bucket.endpoint/key`
    /// — what most self-hosted services want.
    pub path_style: bool,
    /// PEM certificates to trust instead of the Mozilla roots, for an
    /// endpoint with a private CA.
    pub ca_file: Option<PathBuf>,
    pub credentials: Credentials,
    /// Connect and per-read timeouts.
    pub connect_timeout: Duration,
    pub read_timeout: Duration,
}

impl Config {
    /// Check the shape of every field; the endpoint is not contacted.
    pub fn validate(&self) -> Result<()> {
        let bad = |why: &str| Err(Error::Config(why.into()));
        let rest = self
            .endpoint
            .strip_prefix("https://")
            .or_else(|| self.endpoint.strip_prefix("http://"));
        match rest {
            Some(host) if !host.is_empty() && !host.contains(['/', '?', '#', '@', ' ']) => {}
            _ => return bad("endpoint must be http(s)://host[:port] with no path"),
        }
        if self.region.is_empty()
            || self.region.len() > 64
            || !self
                .region
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return bad("region must be 1-64 letters, digits, '-' or '_'");
        }
        let b = self.bucket.as_bytes();
        if !(3..=63).contains(&b.len())
            || !b
                .iter()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-' || *c == b'.')
            || !b[0].is_ascii_alphanumeric()
            || !b[b.len() - 1].is_ascii_alphanumeric()
        {
            return bad("bucket must be 3-63 lower-case letters, digits, '-' or '.'");
        }
        if !self.path_style && self.bucket.contains('.') && self.endpoint.starts_with("https://") {
            return bad("a bucket name with '.' needs path_style over https");
        }
        if !self.prefix.is_empty()
            && (!self.prefix.ends_with('/')
                || self.prefix.starts_with('/')
                || self.prefix.len() > 512
                || self.prefix.split('/').any(|s| s == "." || s == "..")
                || self.prefix.chars().any(char::is_control))
        {
            return bad("prefix must be a relative path ending in '/' (at most 512 bytes)");
        }
        Ok(())
    }
}
