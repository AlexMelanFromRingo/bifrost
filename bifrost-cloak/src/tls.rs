//! Self-signed TLS materials for the `wss://` transport.
//!
//! Same model as norn-rs's QUIC transport: each process generates a
//! self-signed cert at startup. It is NOT used for authentication — the
//! NRN1 handshake *inside* the WebSocket binds peer identity. In TLS 1.3
//! the server Certificate message is encrypted, so a self-signed cert
//! with no real domain is invisible to a passive observer on the path.

use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use rcgen::{CertificateParams, KeyPair};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::{DigitallySignedStruct, SignatureScheme};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};

/// The `ring` crypto provider — matches the rest of the TLS stack.
pub(crate) fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Generate a self-signed Ed25519 certificate for this process lifetime.
pub(crate) fn self_signed_cert() -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
    let key = KeyPair::generate_for(&rcgen::PKCS_ED25519)
        .context("rcgen KeyPair::generate_for ED25519")?;
    let mut params = CertificateParams::new(vec!["localhost".to_string()])
        .context("rcgen CertificateParams")?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    let cert = params.self_signed(&key).context("self-sign cert")?;
    let cert_der = CertificateDer::from(cert.der().to_vec());
    // Decode the private key via rustls-pki-types' built-in PEM parsing.
    use rustls_pki_types::pem::PemObject;
    let key_pem = key.serialize_pem();
    let key_der = PrivateKeyDer::from_pem_slice(key_pem.as_bytes())
        .map_err(|e| anyhow!("rustls-pki-types pem decode: {e:?}"))?;
    Ok((cert_der, key_der))
}

/// Permissive `ServerCertVerifier` — accepts every server cert. The NRN1
/// handshake inside the WebSocket is what actually binds peer identity.
#[derive(Debug)]
pub(crate) struct AcceptAnyServerCert;

impl ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ED25519,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}
