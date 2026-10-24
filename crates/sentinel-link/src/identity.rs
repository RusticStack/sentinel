use std::path::Path;

use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use sentinel_auth::secret::Digest;

use crate::{Error, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    Loaded,
    Generated,
    Recovered,
}

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
    /// `name` is a label for operators reading the certificate; the controller does not trust it.
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

    pub fn fingerprint(&self) -> Digest {
        fingerprint_of(&self.cert)
    }

    pub fn certificate(&self) -> &CertificateDer<'static> {
        &self.cert
    }

    pub(crate) fn into_parts(self) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
        (self.cert, self.key)
    }

    pub fn save(&self, cert_path: &Path, key_path: &Path) -> Result<()> {
        let cert_pem = pem_block("CERTIFICATE", self.cert.as_ref());
        let key_pem = pem_block("PRIVATE KEY", self.key.secret_der());
        // Key first, certificate last: the certificate is the commit marker.
        write_atomic(key_path, key_pem.as_bytes(), true)?;
        write_atomic(cert_path, cert_pem.as_bytes(), false)?;
        Ok(())
    }

    pub fn load_or_generate(
        name: &str,
        cert_path: &Path,
        key_path: &Path,
    ) -> Result<(Identity, Origin)> {
        let (has_cert, has_key) = (cert_path.exists(), key_path.exists());
        if has_cert && has_key {
            return Ok((Identity::load(cert_path, key_path)?, Origin::Loaded));
        }
        if has_cert {
            return Err(Error::Identity(
                "certificate exists without its private key; restore the matching key or remove the certificate to generate a new identity"
                    .into(),
            ));
        }
        let origin = if has_key {
            std::fs::remove_file(key_path)?;
            Origin::Recovered
        } else {
            Origin::Generated
        };
        let generated = Identity::generate(name)?;
        generated.save(cert_path, key_path)?;
        Ok((generated, origin))
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

fn write_atomic(path: &Path, bytes: &[u8], private: bool) -> std::io::Result<()> {
    use std::io::Write;
    let name = path
        .file_name()
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let mut tmp_name = std::ffi::OsString::from(".");
    tmp_name.push(name);
    tmp_name.push(".tmp");
    let tmp = path.with_file_name(tmp_name);
    // A leftover from a crashed save may be readable by others; never reuse it.
    match std::fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    #[cfg(not(unix))]
    let _ = private;
    let written = (|| {
        let mut file = options.open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&tmp, path)
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
        return written;
    }
    #[cfg(unix)]
    {
        let dir = match path.parent() {
            Some(dir) if !dir.as_os_str().is_empty() => dir,
            _ => Path::new("."),
        };
        std::fs::File::open(dir)?.sync_all()?;
    }
    Ok(())
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

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("sentinel-link-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_save_leaves_no_temporary_file_and_replaces_an_earlier_one() {
        let dir = scratch("save");
        let (cert, key) = (dir.join("worker.crt"), dir.join("worker.key"));
        Identity::generate("w").unwrap().save(&cert, &key).unwrap();
        let second = Identity::generate("w").unwrap();
        second.save(&cert, &key).unwrap();
        assert_eq!(
            Identity::load(&cert, &key).unwrap().fingerprint(),
            second.fingerprint()
        );
        let names: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names.len(), 2, "only the two files remain: {names:?}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&key).unwrap().permissions().mode();
            assert_eq!(mode & 0o077, 0, "the key is owner-only");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_lone_key_from_an_interrupted_save_is_replaced() {
        let dir = scratch("torn-key");
        let (cert, key) = (dir.join("worker.crt"), dir.join("worker.key"));
        Identity::generate("w").unwrap().save(&cert, &key).unwrap();
        std::fs::remove_file(&cert).unwrap();
        let (identity, origin) = Identity::load_or_generate("w", &cert, &key).unwrap();
        assert_eq!(origin, Origin::Recovered);
        assert_eq!(
            Identity::load(&cert, &key).unwrap().fingerprint(),
            identity.fingerprint()
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_lone_certificate_is_preserved_and_needs_operator_action() {
        let dir = scratch("torn-cert");
        let (cert, key) = (dir.join("worker.crt"), dir.join("worker.key"));
        Identity::generate("w").unwrap().save(&cert, &key).unwrap();
        std::fs::remove_file(&key).unwrap();
        let certificate = std::fs::read(&cert).unwrap();
        let error = Identity::load_or_generate("w", &cert, &key).unwrap_err();
        assert!(matches!(error, Error::Identity(_)));
        assert!(error.to_string().contains("restore the matching key"));
        assert_eq!(std::fs::read(&cert).unwrap(), certificate);
        assert!(!key.exists(), "no replacement key was created");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_intact_identity_is_loaded_and_a_missing_one_is_generated() {
        let dir = scratch("load");
        let (cert, key) = (dir.join("worker.crt"), dir.join("worker.key"));
        let (made, origin) = Identity::load_or_generate("w", &cert, &key).unwrap();
        assert_eq!(origin, Origin::Generated);
        let (again, origin) = Identity::load_or_generate("w", &cert, &key).unwrap();
        assert_eq!(origin, Origin::Loaded);
        assert_eq!(again.fingerprint(), made.fingerprint());
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
