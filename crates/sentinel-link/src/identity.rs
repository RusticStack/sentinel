//! A generated TLS identity: one self-signed certificate and its key.
//!
//! The fingerprint — BLAKE3 of the certificate's DER — is the identity. The
//! controller stores only that; the key never leaves the machine it was made
//! on. Regenerating means becoming a different worker.

use std::path::Path;

use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use sentinel_auth::secret::Digest;

use crate::{Error, Result};

pub struct Identity {
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Identity({:?})", self.fingerprint())
    }
}

impl Identity {
    /// Generate a fresh identity. `name` is a label inside the certificate for
    /// operators reading it; it is not what the controller trusts.
    pub fn generate(name: &str) -> Result<Identity> {
        let generated = rcgen::generate_simple_self_signed([name.to_owned()])
            .map_err(|e| Error::Identity(e.to_string()))?;
        let key = PrivateKeyDer::try_from(generated.signing_key.serialize_der())
            .map_err(|e| Error::Identity(e.to_string()))?;
        Ok(Identity {
            cert: generated.cert.der().clone(),
            key,
        })
    }

    /// BLAKE3 of the certificate DER: what the other side pins.
    pub fn fingerprint(&self) -> Digest {
        fingerprint_of(&self.cert)
    }

    pub fn certificate(&self) -> &CertificateDer<'static> {
        &self.cert
    }

    pub(crate) fn into_parts(self) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
        (self.cert, self.key)
    }

    /// Persist as two PEM files beside each other. The key file is written
    /// owner-only where the platform supports it; it is the worker's secret.
    pub fn save(&self, cert_path: &Path, key_path: &Path) -> Result<()> {
        let cert_pem = pem_block("CERTIFICATE", self.cert.as_ref());
        let key_pem = pem_block("PRIVATE KEY", self.key.secret_der());
        std::fs::write(cert_path, cert_pem)?;
        write_private(key_path, key_pem.as_bytes())?;
        Ok(())
    }

    pub fn load(cert_path: &Path, key_path: &Path) -> Result<Identity> {
        let cert = CertificateDer::from_pem_file(cert_path)
            .map_err(|e| Error::Identity(format!("certificate: {e}")))?;
        let key = PrivateKeyDer::from_pem_file(key_path)
            .map_err(|e| Error::Identity(format!("key: {e}")))?;
        Ok(Identity { cert, key })
    }
}

pub(crate) fn fingerprint_of(cert: &CertificateDer<'_>) -> Digest {
    Digest(*blake3::hash(cert.as_ref()).as_bytes())
}

fn pem_block(label: &str, der: &[u8]) -> String {
    let mut out = format!("-----BEGIN {label}-----\n");
    let encoded = base64(der);
    for line in encoded.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).expect("base64 is ascii"));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

/// Standard base64 with padding; small enough not to warrant a dependency.
fn base64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n =
            chunk.iter().fold(0u32, |acc, b| (acc << 8) | u32::from(*b)) << (8 * (3 - chunk.len()));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(TABLE[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)
}

#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_identity_round_trips_through_pem_and_keeps_its_fingerprint() {
        let dir = std::env::temp_dir().join(format!("sentinel-link-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let identity = Identity::generate("worker-1").unwrap();
        let (cert, key) = (dir.join("worker.crt"), dir.join("worker.key"));
        identity.save(&cert, &key).unwrap();
        let loaded = Identity::load(&cert, &key).unwrap();
        assert_eq!(loaded.fingerprint(), identity.fingerprint());
        assert_ne!(
            Identity::generate("worker-1").unwrap().fingerprint(),
            identity.fingerprint(),
            "two generations are two identities"
        );
        assert!(!format!("{identity:?}").contains("PRIVATE"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn base64_matches_the_standard_alphabet_and_padding() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
    }
}
