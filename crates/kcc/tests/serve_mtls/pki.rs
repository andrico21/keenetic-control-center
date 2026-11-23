//! Certificates for the mTLS suite, made at run time with rcgen: the server's TLS identity,
//! client CAs and the client certificates they sign; and HTTPS clients presenting one.

extern crate alloc;

use alloc::sync::Arc;
use core::time::Duration;
use std::{
    fs,
    path::{Path, PathBuf},
};

use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
use reqwest::Client;
use rustls::{
    ClientConfig, RootCertStore,
    crypto::ring::default_provider,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};

use crate::TestResult;

/// A client certificate with its key.
pub(crate) struct ClientIdentity {
    /// The certificate's DER.
    cert: CertificateDer<'static>,
    /// The PKCS#8 key's DER.
    key: Vec<u8>,
}

/// A client CA: its PEM and its signer.
pub(crate) struct ClientCa {
    /// The CA certificate as PEM.
    pem: String,
    /// Signs client certificates.
    issuer: Issuer<'static, KeyPair>,
}

impl ClientCa {
    /// A self-signed CA named `name`.
    pub(crate) fn new(name: &str) -> TestResult<Self> {
        let mut params = CertificateParams::new(Vec::<String>::new())?;
        params.distinguished_name.push(DnType::CommonName, name);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let key = KeyPair::generate()?;
        let pem = params.self_signed(&key)?.pem();
        Ok(Self {
            pem,
            issuer: Issuer::new(params, key),
        })
    }

    /// The CA certificate as PEM.
    pub(crate) fn pem(&self) -> &str {
        &self.pem
    }

    /// A client certificate with the common name `name`, signed by this CA.
    pub(crate) fn client(&self, name: &str) -> TestResult<ClientIdentity> {
        let mut params = CertificateParams::new(Vec::<String>::new())?;
        params.distinguished_name.push(DnType::CommonName, name);
        let key = KeyPair::generate()?;
        let cert = params.signed_by(&key, &self.issuer)?;
        Ok(ClientIdentity {
            cert: cert.der().clone(),
            key: key.serialize_der(),
        })
    }
}

/// The server's TLS identity for `localhost` and 127.0.0.1, written to `directory`: the
/// certificate file, the owner-only key file, and the certificate's DER.
pub(crate) fn server_identity(
    directory: &Path,
) -> TestResult<(PathBuf, PathBuf, CertificateDer<'static>)> {
    let key = KeyPair::generate()?;
    let cert = CertificateParams::new(vec!["localhost".to_owned(), "127.0.0.1".to_owned()])?
        .self_signed(&key)?;
    let cert_file = directory.join("server-cert.pem");
    fs::write(&cert_file, cert.pem())?;
    let key_file =
        kcc_testkit::write_secret_file(directory, "server-key.pem", &key.serialize_pem())?;
    Ok((cert_file, key_file, cert.der().clone()))
}

/// An HTTPS client trusting `server` and presenting `identity` when set.
pub(crate) fn https(
    server: &CertificateDer<'static>,
    identity: Option<&ClientIdentity>,
) -> TestResult<Client> {
    let mut roots = RootCertStore::empty();
    roots.add(server.clone())?;
    let builder = ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots);
    let config = match identity {
        Some(client) => builder.with_client_auth_cert(
            vec![client.cert.clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(client.key.clone())),
        )?,
        None => builder.with_no_client_auth(),
    };
    Ok(Client::builder()
        .use_preconfigured_tls(config)
        .timeout(Duration::from_secs(10))
        .build()?)
}
