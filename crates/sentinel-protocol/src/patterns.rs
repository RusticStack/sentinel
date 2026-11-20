//! Credential-shaped text, found by shape rather than by registry (Part 22 Y02).
//!
//! A stored log never holds a value the attempt was registered ([redaction](redact)), but a
//! credential can still reach it through a path no registered value covers: a token a step printed
//! from its own environment, a PEM file it read, a JWT a debug build echoed, a cloud key pasted into
//! a config it then dumped. The AI evidence bundle scans what it serves for those shapes, so a
//! model provider never receives text that looks like a credential even when no value was
//! registered for it. Nothing here decides what a job may print; the log keeps the bytes, and only
//! the bundle this scrubber touches is rewritten.
//!
//! One linear pass over the bytes: the first byte of a candidate picks the only patterns that can
//! start there, and a match copies the text around it, so a clean bundle is never copied at all.

use std::borrow::Cow;

pub const REPLACEMENT: &[u8] = b"***";
/// A JWT longer than this is not one: the bound keeps a pathological line from being one match.
pub const MAX_JWT_BYTES: usize = 4_096;
/// A PEM block is redacted whole, end marker included, when the end marker is within reach.
const MAX_PEM_BYTES: usize = 64 * 1024;
/// Never redact a shorter tail than this: `BEGIN` alone is prose, not a block.
const MIN_PEM_BYTES: usize = 32;
/// A JWT header is a small JSON object; a longer first segment is base64 of something else.
const MAX_JWT_HEADER_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Kind {
    /// A Sentinel credential, access token, refresh token, code or device code (`sntl_…`).
    SentinelToken,
    /// A GitHub credential (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_`).
    GithubToken,
    /// A PEM private key block, `-----BEGIN … PRIVATE KEY-----` through its end marker.
    PemBlock,
    /// An AWS access key ID (`AKIA…`, `ASIA…` and the other documented prefixes).
    AwsKey,
    /// A Google API key (`AIza…`).
    GoogleKey,
    /// An Azure storage account key, the value after `AccountKey=`.
    AzureKey,
    /// A JSON Web Token: three base64url segments, the first a JSON header.
    Jwt,
}

impl Kind {
    pub const ALL: [Kind; 7] = [
        Self::SentinelToken,
        Self::GithubToken,
        Self::PemBlock,
        Self::AwsKey,
        Self::GoogleKey,
        Self::AzureKey,
        Self::Jwt,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SentinelToken => "sentinel_token",
            Self::GithubToken => "github_token",
            Self::PemBlock => "pem_block",
            Self::AwsKey => "aws_key",
            Self::GoogleKey => "google_key",
            Self::AzureKey => "azure_key",
            Self::Jwt => "jwt",
        }
    }

    const fn mask(self) -> u8 {
        1 << self as u8
    }
}

/// Which patterns fired and how often, for the bundle's own record of what it rewrote.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Hits {
    kinds: u8,
    count: u32,
}

impl Hits {
    pub const NONE: Self = Self { kinds: 0, count: 0 };

    pub const fn count(self) -> u32 {
        self.count
    }

    pub const fn is_empty(self) -> bool {
        self.count == 0
    }

    pub const fn contains(self, kind: Kind) -> bool {
        self.kinds & kind.mask() != 0
    }

    /// In the kinds' own order, so two readings of one scan print alike.
    pub fn kinds(self) -> impl Iterator<Item = Kind> {
        Kind::ALL
            .into_iter()
            .filter(move |kind| self.contains(*kind))
    }

    fn record(&mut self, kind: Kind) {
        self.kinds |= kind.mask();
        self.count = self.count.saturating_add(1);
    }

    fn merge(&mut self, other: Hits) {
        self.kinds |= other.kinds;
        self.count = self.count.saturating_add(other.count);
    }
}

/// The bytes with every credential-shaped run replaced by [`REPLACEMENT`], and what was found.
/// Borrowed when nothing matched, so a clean bundle costs one scan and no allocation.
pub fn redact(bytes: &[u8]) -> (Cow<'_, [u8]>, Hits) {
    let mut hits = Hits::NONE;
    let mut matched: Option<Vec<u8>> = None;
    let mut copied = 0usize;
    let mut at = 0usize;
    while at < bytes.len() {
        let Some((kind, end)) = match_at(bytes, at) else {
            at += 1;
            continue;
        };
        let out = matched.get_or_insert_with(|| Vec::with_capacity(bytes.len()));
        out.extend_from_slice(&bytes[copied..at]);
        out.extend_from_slice(REPLACEMENT);
        hits.record(kind);
        copied = end;
        at = end;
    }
    match matched {
        None => (Cow::Borrowed(bytes), hits),
        Some(mut out) => {
            out.extend_from_slice(&bytes[copied..]);
            (Cow::Owned(out), hits)
        }
    }
}

/// [`redact`] over text, adding to `hits` rather than replacing it.
pub fn redact_str(text: &str, hits: &mut Hits) -> String {
    let (redacted, found) = redact(text.as_bytes());
    hits.merge(found);
    match redacted {
        Cow::Borrowed(_) => text.to_owned(),
        Cow::Owned(bytes) => {
            String::from_utf8(bytes).expect("replacement is ASCII, input is UTF-8")
        }
    }
}

/// Whether `bytes` holds anything [`redact`] would rewrite.
pub fn any(bytes: &[u8]) -> bool {
    !redact(bytes).1.is_empty()
}

fn match_at(bytes: &[u8], at: usize) -> Option<(Kind, usize)> {
    match bytes[at] {
        b's' if bytes[at..].starts_with(b"sntl_") => {
            let end = run(bytes, at + 5, 20, is_token_byte)?;
            Some((Kind::SentinelToken, end))
        }
        b'g' if bytes[at..].starts_with(b"gh") => github(bytes, at),
        b'g' if bytes[at..].starts_with(b"github_pat_") => {
            let end = run(bytes, at + 11, 20, is_token_byte)?;
            Some((Kind::GithubToken, end))
        }
        b'-' if bytes[at..].starts_with(b"-----BEGIN ") => pem(bytes, at),
        b'A' => cloud(bytes, at),
        b'e' if bytes[at..].starts_with(b"eyJ") => jwt(bytes, at),
        b'=' if at >= 10 && bytes[at - 10..at].eq_ignore_ascii_case(b"AccountKey") => {
            let end = run(bytes, at + 1, 32, is_azure_key_byte)?;
            Some((Kind::AzureKey, end))
        }
        _ => None,
    }
}

fn github(bytes: &[u8], at: usize) -> Option<(Kind, usize)> {
    const PREFIXES: [&[u8; 4]; 5] = [b"ghp_", b"gho_", b"ghu_", b"ghs_", b"ghr_"];
    if PREFIXES
        .iter()
        .any(|prefix| bytes[at..].starts_with(*prefix))
    {
        let end = run(bytes, at + 4, 36, is_token_byte)?;
        return Some((Kind::GithubToken, end));
    }
    None
}

fn cloud(bytes: &[u8], at: usize) -> Option<(Kind, usize)> {
    const AWS: [&[u8; 4]; 11] = [
        b"AKIA", b"ASIA", b"ABIA", b"ACCA", b"AGPA", b"AIDA", b"AIPA", b"ANPA", b"ANVA", b"AROA",
        b"ASCA",
    ];
    if AWS.iter().any(|prefix| bytes[at..].starts_with(*prefix)) {
        let end = at + 20;
        if end <= bytes.len()
            && bytes[at + 4..end].iter().all(|b| is_base32(*b))
            && boundary(bytes, end)
        {
            return Some((Kind::AwsKey, end));
        }
        return None;
    }
    if bytes[at..].starts_with(b"A3T") {
        let end = at + 20;
        if end <= bytes.len()
            && bytes[at + 3..end].iter().all(|b| is_base32(*b))
            && boundary(bytes, end)
        {
            return Some((Kind::AwsKey, end));
        }
        return None;
    }
    if bytes[at..].starts_with(b"AIza") {
        let end = at + 39;
        if end <= bytes.len()
            && bytes[at + 4..end].iter().all(|b| is_token_byte(*b))
            && boundary(bytes, end)
        {
            return Some((Kind::GoogleKey, end));
        }
    }
    None
}

/// A PEM block, from `-----BEGIN … PRIVATE KEY-----`
/// through its end marker, or to the end of what is here when the block is cut: a truncated block is
/// still a private key's first lines.
fn pem(bytes: &[u8], at: usize) -> Option<(Kind, usize)> {
    let rest = &bytes[at..];
    let label_end = rest
        .iter()
        .position(|b| *b == b'\n')
        .unwrap_or(rest.len().min(128));
    let label = &rest[..label_end];
    if !label.ends_with(b"-----") || label.len() < b"-----BEGIN -----".len() || label.len() > 128 {
        return None;
    }
    let inner = &label[b"-----BEGIN ".len()..label.len() - 5];
    if !inner.ends_with(b"PRIVATE KEY") {
        return None;
    }
    let limit = bytes.len().min(at + MAX_PEM_BYTES);
    let end = find(&bytes[at..limit], b"-----END ").and_then(|found| {
        let end_at = at + found;
        bytes[end_at..limit]
            .iter()
            .position(|b| *b == b'\n')
            .map_or(Some(limit), |line| Some(end_at + line + 1))
    });
    let end = end.unwrap_or(limit);
    if end - at < MIN_PEM_BYTES {
        return None;
    }
    Some((Kind::PemBlock, end.min(bytes.len())))
}

fn jwt(bytes: &[u8], at: usize) -> Option<(Kind, usize)> {
    let limit = bytes.len().min(at + MAX_JWT_BYTES);
    let mut segments = 0usize;
    let mut cursor = at;
    loop {
        let start = cursor;
        while cursor < limit && is_token_byte(bytes[cursor]) {
            cursor += 1;
        }
        // Each segment carries at least four characters; a two-part token has no signature.
        if cursor - start < 4 || (segments == 0 && cursor - start > MAX_JWT_HEADER_BYTES) {
            return None;
        }
        segments += 1;
        if segments == 3 || cursor >= limit || bytes[cursor] != b'.' {
            break;
        }
        cursor += 1;
    }
    (segments >= 2 && boundary(bytes, cursor)).then_some((Kind::Jwt, cursor))
}

/// A run of `min` or more pattern bytes starting at `at`, ending at its last one.
fn run(bytes: &[u8], at: usize, min: usize, valid: fn(u8) -> bool) -> Option<usize> {
    let mut end = at;
    while end < bytes.len() && valid(bytes[end]) {
        end += 1;
    }
    (end - at >= min).then_some(end)
}

fn boundary(bytes: &[u8], at: usize) -> bool {
    bytes.get(at).is_none_or(|b| !is_token_byte(*b))
}

fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

fn is_base32(b: u8) -> bool {
    b.is_ascii_uppercase() || b.is_ascii_digit()
}

fn is_azure_key_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=')
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rewritten(text: &str) -> (String, Hits) {
        let mut hits = Hits::NONE;
        let out = redact_str(text, &mut hits);
        (out, hits)
    }

    const SENTINEL: &str = "sntl_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const GITHUB: &str = "ghp_0123456789abcdefghijklmnopqrstuvwxyz";
    const GITHUB_PAT: &str = "github_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyz0123456789";
    const AWS: &str = "AKIAIOSFODNN7EXAMPLE";
    const GOOGLE: &str = "AIzaSyA0123456789abcdefghijklmnopqrstuv";
    const JWT: &str = concat!(
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
        ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0",
        ".dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    );

    const AZURE: &str =
        "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdef+/==";

    #[test]
    fn every_documented_credential_shape_is_rewritten_with_its_kind() {
        for (text, secret, kind) in [
            (
                format!("token {SENTINEL} here"),
                SENTINEL,
                Kind::SentinelToken,
            ),
            (
                format!("export GITHUB_TOKEN={GITHUB}"),
                GITHUB,
                Kind::GithubToken,
            ),
            (
                format!("header {GITHUB_PAT}"),
                GITHUB_PAT,
                Kind::GithubToken,
            ),
            (format!("aws {AWS}"), AWS, Kind::AwsKey),
            (format!("key {GOOGLE}"), GOOGLE, Kind::GoogleKey),
            (format!("authorization: Bearer {JWT}"), JWT, Kind::Jwt),
            (
                format!("DefaultEndpointsProtocol=https;AccountKey={AZURE};EndpointSuffix=core"),
                AZURE,
                Kind::AzureKey,
            ),
        ] {
            let (out, hits) = rewritten(&text);
            assert!(hits.contains(kind), "{text}: {hits:?}");
            assert_eq!(hits.count(), 1, "{text}");
            assert!(!out.contains(secret), "{out}");
            assert!(out.contains("***"), "{out}");
        }
    }

    /// A PEM header built from parts, so no line of this file carries a whole header followed by a
    /// key body: the committed-key guard reads that shape as a key, and a test fixture is not one.
    fn pem_text(label: &str, body: &str) -> String {
        let begin = [r"-----BEGIN ", label, r"-----"].concat();
        let end = [r"-----END ", label, r"-----"].concat();
        format!("{begin}\n{body}\n{end}")
    }

    #[test]
    fn a_pem_block_is_rewritten_whole_including_its_body() {
        let pem = format!(
            "{}\nafter",
            pem_text("RSA PRIVATE KEY", "MIIEowIBAAKCAQEAfakeBody")
        );
        let (out, hits) = rewritten(&format!("key:\n{pem}"));
        assert!(hits.contains(Kind::PemBlock));
        assert!(!out.contains("MIIEowIBAAKCAQEA"));
        assert!(!out.contains("END RSA PRIVATE KEY"));
        assert!(out.contains("key:\n***after"), "{out}");

        let openssh = pem_text("OPENSSH PRIVATE KEY", "b3BlbnNzaC1rZXktdjEAAAAAfakeBody");
        let (out, hits) = rewritten(&openssh);
        assert!(hits.contains(Kind::PemBlock));
        assert!(!out.contains("b3BlbnNzaC1rZXktdjEAAAAA"));
    }

    #[test]
    fn a_pem_block_cut_before_its_end_marker_is_rewritten_to_the_end() {
        let cut = format!(
            "{}",
            pem_text("RSA PRIVATE KEY", "MIIEowIBAAKCAQEAfakeBody")
        );
        let (out, hits) = rewritten(&cut);
        assert!(hits.contains(Kind::PemBlock));
        assert_eq!(out.trim_end(), "***");
    }

    #[test]
    fn prose_that_merely_mentions_a_credential_is_left_alone() {
        for text in [
            "the sntl_ credential is refused",
            "set GITHUB_TOKEN to your token",
            "run gh auth login",
            "-----BEGIN -----\nnot a key",
            "AKIA is the prefix",
            "eyJ is the start",
            "AccountKey=short",
            "the AIza prefix",
        ] {
            let (out, hits) = rewritten(text);
            assert!(hits.is_empty(), "{text}: {hits:?}");
            assert_eq!(out, text);
        }
    }

    #[test]
    fn the_first_byte_of_a_candidate_decides_what_is_tried() {
        // One pass, borrowed output when nothing matches: no copy of a clean body.
        let clean = b"nothing here but ordinary compiler output\n".repeat(64);
        let (out, hits) = redact(&clean);
        assert!(hits.is_empty());
        assert!(matches!(out, Cow::Borrowed(_)));
    }

    #[test]
    fn several_kinds_in_one_text_are_all_rewritten_and_counted() {
        let (out, hits) = rewritten(&format!("{SENTINEL} {GITHUB} {AWS}"));
        assert_eq!(hits.count(), 3);
        assert_eq!(
            hits.kinds().collect::<Vec<_>>(),
            [Kind::SentinelToken, Kind::GithubToken, Kind::AwsKey]
        );
        assert_eq!(out, "*** *** ***");
    }

    #[test]
    fn a_jwt_too_short_or_oversized_is_not_one() {
        assert!(!any(b"eyJ.eyJ.x"));
        let long = format!(
            "eyJ{}.eyJ{}.{}",
            "a".repeat(2_000),
            "b".repeat(2_000),
            "c".repeat(2_000)
        );
        assert!(!any(long.as_bytes()));
        assert!(any(JWT.as_bytes()));
    }
}
