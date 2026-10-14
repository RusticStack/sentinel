//! TLS in both directions, pinned rather than delegated.
//!
//! The controller requires a client certificate and accepts any well-formed
//! one at the TLS layer: *which* fingerprints are live workers is the store's
//! decision, made after the handshake with the certificate in hand. The worker
//! accepts only the server fingerprints it was configured with: the one it
//! was enrolled with and, for a certificate rotation, further ones the
//! operator names (at most [`MAX_PINS`] in all). No root store is consulted
//! on either side, so a compromised public CA cannot insert itself, and trust
//! changes only by an explicit configuration edit, never silently.

use std::sync::Arc;

use rustls::{
    ClientConfig, DigitallySignedStruct, ServerConfig, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{CryptoProvider, WebPkiSupportedAlgorithms, ring},
    pki_types::{CertificateDer, ServerName, UnixTime},
    server::danger::{ClientCertVerified, ClientCertVerifier},
};
use sentinel_auth::secret::{Digest, digest_eq};

use crate::{Error, Result, identity::Identity};

fn provider() -> Arc<CryptoProvider> {
    Arc::new(ring::default_provider())
}

fn algorithms() -> WebPkiSupportedAlgorithms {
    ring::default_provider().signature_verification_algorithms
}

/// Accept any syntactically valid client certificate; identity is decided by
/// fingerprint after the handshake. The handshake signature is still verified
/// against the certificate's own key, so the peer proves possession.
#[derive(Debug)]
struct AnyClient;

impl ClientCertVerifier for AnyClient {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }
    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> std::result::Result<ClientCertVerified, rustls::Error> {
        if end_entity.as_ref().is_empty() {
            return Err(rustls::Error::General("empty certificate".into()));
        }
        Ok(ClientCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &algorithms())
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &algorithms())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        algorithms().supported_schemes()
    }
}

/// Most fingerprints a worker may pin at once: the current certificate, the
/// next one during a rotation, and a little slack. Bounded so a typo cannot
/// turn the pin into a list.
pub const MAX_PINS: usize = 4;

/// Accept only the pinned servers: the fingerprint the worker was enrolled
/// with plus the operator-named ones of a rotation overlap.
#[derive(Debug)]
struct PinnedServer(Vec<Digest>);

impl ServerCertVerifier for PinnedServer {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let presented = crate::identity::fingerprint_of(end_entity);
        // Every pin is compared; which one matched is not observable.
        let mut matched = false;
        for pin in &self.0 {
            matched |= digest_eq(&presented, pin);
        }
        if matched {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General("server fingerprint mismatch".into()))
        }
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &algorithms())
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &algorithms())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        algorithms().supported_schemes()
    }
}

/// Controller-side configuration: present `identity`, demand a client
/// certificate, decide identity by fingerprint afterwards.
pub fn server_config(identity: Identity) -> Result<Arc<ServerConfig>> {
    let (cert, key) = identity.into_parts();
    let config = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| Error::Tls(e.to_string()))?
        .with_client_cert_verifier(Arc::new(AnyClient))
        .with_single_cert(vec![cert], key)
        .map_err(|e| Error::Tls(e.to_string()))?;
    Ok(Arc::new(config))
}

/// Worker-side configuration: present `identity`, accept only `server`.
pub fn client_config(identity: Identity, server: Digest) -> Result<Arc<ClientConfig>> {
    client_config_pinned(identity, &[server])
}

/// [`client_config`] for a controller certificate rotation: accept any of
/// `servers` (at least one, at most [`MAX_PINS`]). The overlap is the
/// operator's: the old and the new fingerprint are both listed until every
/// worker has reconnected to the rotated controller, then the old one goes.
pub fn client_config_pinned(identity: Identity, servers: &[Digest]) -> Result<Arc<ClientConfig>> {
    if servers.is_empty() || servers.len() > MAX_PINS {
        return Err(Error::Tls("controller pins".into()));
    }
    let (cert, key) = identity.into_parts();
    let config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| Error::Tls(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedServer(servers.to_vec())))
        .with_client_auth_cert(vec![cert], key)
        .map_err(|e| Error::Tls(e.to_string()))?;
    Ok(Arc::new(config))
}
