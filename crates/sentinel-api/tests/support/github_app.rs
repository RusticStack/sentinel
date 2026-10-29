#![allow(dead_code)]
//! What the GitHub App tests share (`tests/github_app.rs`, `tests/web_browser.rs`): the per-process
//! test key, the canary credentials the fake hands back once, and the scans that prove none of
//! them reaches an answer, a log, an audit row or a database file.

use sentinel_github::fake::Blueprint;

pub const CLIENT_SECRET: &str = "client-secret-canary-6f1d2a9e0b7c4d3e8f5a";
pub const WEBHOOK_SECRET: &str = "webhook-secret-canary-3e9f0a1b2c7d4e5f6a8b";
/// Any copy of the private key, whatever its encoding, starts with this line.
pub const PEM_MARKER: &str = "-----BEGIN PRIVATE KEY-----";

/// A test-only RSA key generated fresh for this process with the `openssl` CLI; it authenticates nothing and no
/// private key is committed (see `no_committed_keys` in the `sentinel` crate tests).
pub fn test_key() -> &'static str {
    static KEY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    KEY.get_or_init(|| {
        let out = std::process::Command::new("openssl")
            .args([
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
            ])
            .output()
            .expect("the openssl CLI must be installed to generate the test-only App key");
        assert!(out.status.success(), "openssl genpkey failed");
        String::from_utf8(out.stdout).expect("PEM is ASCII")
    })
}

/// A run of the private key's body, taken from a line of random key material (the first body lines of
/// a PKCS#8 key are the same in every key), so it is in the key and in nothing else. It is derived from
/// the generated key: a constant copied from some other key could never occur and would scan nothing.
pub fn key_canary() -> &'static str {
    static CANARY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    CANARY.get_or_init(|| {
        let body: Vec<&str> = test_key()
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        let line = body
            .get(7)
            .expect("a 2048-bit key has more than 7 body lines");
        assert!(line.len() >= 48, "{} base64 characters", line.len());
        line[..40].to_owned()
    })
}

/// Everything that must stay out of answers, logs, audit rows and database files.
pub fn canaries() -> [&'static str; 4] {
    [key_canary(), CLIENT_SECRET, WEBHOOK_SECRET, PEM_MARKER]
}

/// The App the fake's web pages create. `web` is the fake's API origin, the address of the App's page.
pub fn blueprint(owner_login: &str) -> Blueprint {
    Blueprint {
        id: 4242,
        slug: "acme-ci".into(),
        name: "Acme CI".into(),
        owner_login: owner_login.into(),
        owner_id: 9000,
        owner_kind: "Organization".into(),
        client_id: "Iv23.acmeclient".into(),
        client_secret: CLIENT_SECRET.into(),
        webhook_secret: WEBHOOK_SECRET.into(),
        pem: test_key().to_owned(),
    }
}

/// The positive control: the canaries occur in what the fake serves. Without this a scan that finds
/// nothing could be a scan of the wrong thing.
pub fn assert_present_in_source(source: &str) {
    for canary in canaries() {
        assert!(
            source.contains(canary),
            "the canary {canary:?} is not in the credentials the fake hands out: the scan would find nothing"
        );
    }
}

/// Panics naming the place when `text` holds a canary.
pub fn assert_clean_text(place: &str, text: &str) {
    for canary in canaries() {
        assert!(!text.contains(canary), "{canary} in {place}");
    }
}

/// The SQLite database and its write-ahead log in `dir`: no canary in a byte of either.
pub fn assert_clean_database(dir: &std::path::Path) {
    let mut found = 0;
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if !name.starts_with("metadata.sqlite") {
            continue;
        }
        found += 1;
        let bytes = std::fs::read(&path).unwrap();
        for canary in canaries() {
            assert!(
                !bytes.windows(canary.len()).any(|w| w == canary.as_bytes()),
                "{canary} in {name}"
            );
        }
    }
    assert!(found > 0, "no database file under {}", dir.display());
}
