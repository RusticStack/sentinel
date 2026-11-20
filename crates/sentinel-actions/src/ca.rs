//! The certificate authority one sandbox gets, and the trust anchor it leaves behind.
//!
//! A runner's cache and artifact clients only speak HTTPS to the hosts GitHub named, so serving them
//! locally means terminating TLS for exactly those names. A worker-wide authority would make every
//! sandbox's key able to impersonate them for every other sandbox, so the authority is minted **per
//! sandbox**: one CA key, one leaf covering [`HOSTS`](crate::HOSTS), one anchor file inside the
//! sandbox's own directory. Nothing writes it to a host trust store, and a client that does not carry
//! the anchor cannot complete a handshake with the endpoint, which is [`refused_outside`].

use std::{fs, os::unix::fs::OpenOptionsExt, path::Path, sync::Arc};

use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};
use rustls::ServerConfig;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use crate::{Error, HOSTS, Result};

/// Where the anchor lives inside the sandbox: the only path that ever holds the CA certificate, and a
/// read-only mount of the sandbox's own staged file on the host.
pub const CA_PATH: &str = "/sentinel-ca/ca.crt";

/// The environment variable the pinned clients' Node runtime reads an extra anchor from. Node appends
/// it to the platform store, so every other host keeps the image's roots and GitHub's own traffic is
/// untouched; it is a path, never a secret.
pub const CA_ENV: &str = "NODE_EXTRA_CA_CERTS";

/// One sandbox's authority and the server identity it signed.
pub struct SandboxCa {
    anchor: CertificateDer<'static>,
    leaf: CertificateDer<'static>,
    key: PrivatePkcs8KeyDer<'static>,
    anchor_pem: Vec<u8>,
    fingerprint: [u8; 32],
}

impl SandboxCa {
    /// Mints the authority of one sandbox. `label` names it in the certificate and reaches no log.
    pub fn generate(label: &str) -> Result<SandboxCa> {
        let ca_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .map_err(|e| Error::Ca(e.to_string()))?;
        let mut params =
            CertificateParams::new(Vec::<String>::new()).map_err(|e| Error::Ca(e.to_string()))?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        params
            .distinguished_name
            .push(DnType::CommonName, format!("Sentinel sandbox {label}"));
        let ca = params
            .self_signed(&ca_key)
            .map_err(|e| Error::Ca(e.to_string()))?;
        let issuer = rcgen::Issuer::from_params(&params, &ca_key);

        let leaf_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .map_err(|e| Error::Ca(e.to_string()))?;
        let mut leaf_params = CertificateParams::new(
            HOSTS
                .iter()
                .map(|host| (*host).to_owned())
                .collect::<Vec<String>>(),
        )
        .map_err(|e| Error::Ca(e.to_string()))?;
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, HOSTS[0]);
        leaf_params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        leaf_params.use_authority_key_identifier_extension = true;
        let leaf = leaf_params
            .signed_by(&leaf_key, &issuer)
            .map_err(|e| Error::Ca(e.to_string()))?;

        let anchor = ca.der().clone();
        let anchor_pem = ca.pem().into_bytes();
        let fingerprint = *blake3::hash(anchor.as_ref()).as_bytes();
        Ok(SandboxCa {
            anchor,
            leaf: leaf.der().clone(),
            key: PrivatePkcs8KeyDer::from(leaf_key.serialize_der()),
            anchor_pem,
            fingerprint,
        })
    }

    /// The anchor's BLAKE3, which is how "this certificate is that sandbox's" is checked without a key.
    pub fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }

    /// The CA certificate alone, PEM: what the sandbox trusts, and all it is told.
    pub fn anchor_pem(&self) -> &[u8] {
        &self.anchor_pem
    }

    /// The anchor in DER: what a client's root store is given.
    pub fn anchor_der(&self) -> CertificateDer<'static> {
        self.anchor.clone()
    }

    /// The leaf chain the endpoint presents: the leaf, then the authority that signed it.
    pub fn chain(&self) -> Vec<CertificateDer<'static>> {
        vec![self.leaf.clone(), self.anchor.clone()]
    }

    /// The TLS configuration the endpoint serves this sandbox with. No client certificate is asked for:
    /// a sandbox proves itself by carrying the anchor, and a client without it fails verification.
    pub fn server_config(&self) -> Result<Arc<ServerConfig>> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let key = PrivateKeyDer::from(self.key.clone_key());
        let config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| Error::Tls(e.to_string()))?
            .with_no_client_auth()
            .with_single_cert(self.chain(), key)
            .map_err(|e| Error::Tls(e.to_string()))?;
        Ok(Arc::new(config))
    }

    /// Writes the anchor into the sandbox's own directory, owner-readable and world-readable because a
    /// container user reads it, never shared with another sandbox's directory.
    pub fn write_anchor(&self, dir: &Path) -> Result<std::path::PathBuf> {
        fs::create_dir_all(dir)?;
        let path = dir.join("ca.crt");
        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(true).mode(0o644);
        let mut file = options.open(&path)?;
        std::io::Write::write_all(&mut file, &self.anchor_pem)?;
        file.sync_all()?;
        Ok(path)
    }
}

impl std::fmt::Debug for SandboxCa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SandboxCa({})", hex(&self.fingerprint))
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[usize::from(byte >> 4)] as char);
        out.push(DIGITS[usize::from(byte & 0xf)] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};

    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "sentinel-actions-ca-{name}-{}-{:x}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn every_sandbox_gets_its_own_authority_and_anchor() {
        let a = SandboxCa::generate("lease-a").unwrap();
        let b = SandboxCa::generate("lease-b").unwrap();
        assert_ne!(a.fingerprint(), b.fingerprint());
        assert!(a.anchor_pem().starts_with(b"-----BEGIN CERTIFICATE-----"));
        assert_eq!(
            a.anchor_pem(),
            a.anchor_pem(),
            "the anchor is the certificate, not a key"
        );
        assert!(!String::from_utf8_lossy(a.anchor_pem()).contains("PRIVATE KEY"));
        assert_eq!(a.chain().len(), 2, "leaf then its authority");
    }

    /// The sandbox's anchor is written under the sandbox's directory and nothing else: a fresh write
    /// leaves exactly one file, and the CA key never appears in it.
    #[test]
    fn the_anchor_is_written_only_inside_the_sandbox_directory() {
        let dir = scratch("anchor");
        let ca = SandboxCa::generate("lease").unwrap();
        let path = ca.write_anchor(&dir).unwrap();
        assert_eq!(path, dir.join("ca.crt"));
        let names: Vec<String> = fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, ["ca.crt"]);
        let written = fs::read(&path).unwrap();
        assert_eq!(written, ca.anchor_pem());
        fs::remove_dir_all(&dir).unwrap();
    }

    /// A client that carries the sandbox's anchor completes a TLS handshake against the leaf; a client
    /// without it is refused by verification, which is what "the CA never leaves its sandbox" means on
    /// the wire.
    #[test]
    fn a_client_without_the_sandbox_anchor_is_refused_and_one_with_it_is_not() {
        let ca = SandboxCa::generate("lease").unwrap();
        let config = ca.server_config().unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            for _ in 0..2 {
                let (mut tcp, _) = listener.accept().unwrap();
                let Ok(mut tls) = rustls::ServerConnection::new(Arc::clone(&config)) else {
                    continue;
                };
                let mut stream = rustls::Stream::new(&mut tls, &mut tcp);
                let _ = stream.write_all(b"x");
                let mut one = [0u8; 1];
                let _ = stream.read(&mut one);
            }
        });

        let client = |roots: Vec<CertificateDer<'static>>| {
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let mut store = rustls::RootCertStore::empty();
            for root in roots {
                store.add(root).unwrap();
            }
            let config = rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(store)
                .with_no_client_auth();
            let name = rustls_pki_types::ServerName::try_from(crate::CACHE_HOST).unwrap();
            rustls::ClientConnection::new(Arc::new(config), name).unwrap()
        };
        let read_one = |mut conn: rustls::ClientConnection| {
            let mut tcp = std::net::TcpStream::connect(addr).unwrap();
            let mut stream = rustls::Stream::new(&mut conn, &mut tcp);
            let mut byte = [0u8; 1];
            stream.read_exact(&mut byte).map(|()| byte)
        };

        // Outside the sandbox: nothing on this machine carries this sandbox's anchor.
        assert!(
            read_one(client(Vec::new())).is_err(),
            "a client without the anchor completed a handshake"
        );
        // Inside the sandbox: this sandbox's anchor is the whole difference.
        assert_eq!(read_one(client(vec![ca.anchor_der()])).unwrap(), *b"x");
        let _ = server.join();
    }

    #[test]
    fn the_debug_form_names_the_fingerprint_and_no_key_material() {
        let ca = SandboxCa::generate("lease").unwrap();
        let text = format!("{ca:?}");
        assert!(text.contains(&hex(&ca.fingerprint())));
        assert!(!text.contains("PRIVATE"));
    }
}
