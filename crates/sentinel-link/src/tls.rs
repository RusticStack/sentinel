//! TLS in both directions, pinned rather than delegated.
//!
//! The controller requires a client certificate and accepts any well-formed
//! one at the TLS layer: *which* fingerprints are live workers is the store's
//! decision, made after the handshake with the certificate in hand. The worker
//! accepts exactly one server fingerprint, the one it was enrolled with. No
//! root store is consulted on either side, so a compromised public CA cannot
//! insert itself, and a rotated controller certificate is an explicit
//! re-enrollment, not a silent change of trust.

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

/// Accept exactly one server: the fingerprint the worker was enrolled with.
#[derive(Debug)]
struct PinnedServer(Digest);

impl ServerCertVerifier for PinnedServer {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        if digest_eq(&crate::identity::fingerprint_of(end_entity), &self.0) {
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
    let (cert, key) = identity.into_parts();
    let config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| Error::Tls(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedServer(server)))
        .with_client_auth_cert(vec![cert], key)
        .map_err(|e| Error::Tls(e.to_string()))?;
    Ok(Arc::new(config))
}
