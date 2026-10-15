// No root store is consulted on either side: a compromised public CA must not be able to
// add itself as a trusted peer. Trust changes only through explicit configuration.

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

pub const MAX_PINS: usize = 4;

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

pub fn client_config(identity: Identity, server: Digest) -> Result<Arc<ClientConfig>> {
    client_config_pinned(identity, &[server])
}

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
