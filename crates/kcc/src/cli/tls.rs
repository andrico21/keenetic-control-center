//! Shell completions, the self-signed server certificate, and the container healthcheck.

extern crate alloc;

use alloc::sync::Arc;
use core::{fmt, net::SocketAddr, time::Duration};
use std::io::{self, Write as _};

use clap::CommandFactory as _;
use clap_complete::Shell;
use kcc_app::settings::default_config_dir;
use kcc_i18n::keys;
use reqwest::{Client, StatusCode, redirect::Policy};
use rustls::{
    DigitallySignedStruct, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{CryptoProvider, ring, verify_tls12_signature, verify_tls13_signature},
    pki_types::{CertificateDer, ServerName, UnixTime, pem::PemObject as _},
};
use serde_json::json;
use sha2::{Digest as _, Sha256};

use super::{
    args::Cli,
    args_admin::TlsCommand,
    context::{Globals, load_config},
    exit::{Exit, Failure, Outcome},
    files,
    output::Out,
};

/// How long the healthcheck waits for `/healthz`.
const HEALTH_TIMEOUT: Duration = Duration::from_secs(5);

/// Prints the completion script of `shell`.
///
/// # Errors
///
/// Returns stdout failures.
pub(crate) fn completions(shell: Shell) -> Outcome {
    let mut stdout = io::stdout().lock();
    clap_complete::generate(shell, &mut Cli::command(), "kcc", &mut stdout);
    stdout.flush()?;
    Ok(())
}

/// Writes a self-signed certificate and its key, printing the certificate's SHA-256.
///
/// # Errors
///
/// Returns generation or file failures; existing files are never replaced.
pub(crate) fn self_signed(out: Out, command: TlsCommand) -> Outcome {
    let TlsCommand::SelfSigned { hosts, out_dir } = command;
    let dir = out_dir.or_else(default_config_dir).ok_or_else(|| {
        Failure::text(
            Exit::Usage,
            &"no --out-dir and no platform config directory",
        )
    })?;
    let generated = rcgen::generate_simple_self_signed(hosts)
        .map_err(|error| Failure::text(Exit::Generic, &error))?;
    files::private_dir(&dir)?;
    let cert_path = dir.join("kcc-cert.pem");
    let key_path = dir.join("kcc-key.pem");
    files::write_private(&cert_path, generated.cert.pem().as_bytes(), true)?;
    files::write_private(
        &key_path,
        generated.signing_key.serialize_pem().as_bytes(),
        true,
    )?;
    let fingerprint = hex(&Sha256::digest(generated.cert.der()));
    let document = json!({
        "certificate": cert_path,
        "key": key_path,
        "sha256": fingerprint,
    });
    let human = out.tr(
        keys::CLI_TLS_WRITTEN,
        &[
            ("path", &cert_path.display().to_string()),
            ("value", &fingerprint),
        ],
    );
    out.emit(&document, &human)
}

/// One GET of `/healthz` on the configured loopback port; exit 0 only on HTTP 200.
///
/// With listener TLS the request uses `https` with SNI set to the host of
/// `[web] public_url` (else `localhost`) and trusts exactly the configured certificate.
///
/// # Errors
///
/// Returns a generic failure for anything but HTTP 200.
// cancel-safe: one read-only request.
pub(crate) async fn healthcheck(globals: &Globals) -> Outcome {
    let config = load_config(globals.config())?;
    let port = config.server.listen_port;
    let loopback = SocketAddr::from(([127, 0, 0, 1], port));
    drop(ring::default_provider().install_default());
    let builder = Client::builder()
        .timeout(HEALTH_TIMEOUT)
        .redirect(Policy::none())
        .no_proxy();
    let (client, url) = if let (Some(cert), Some(_key)) =
        (&config.server.tls_cert_path, &config.server.tls_key_path)
    {
        {
            let host = config
                .web
                .public_url
                .as_ref()
                .and_then(|url| url.host_str().map(str::to_owned))
                .unwrap_or_else(|| "localhost".to_owned());
            let leaf = CertificateDer::pem_file_iter(cert)
                .map_err(|error| Failure::text(Exit::Generic, &error))?
                .next()
                .ok_or_else(|| {
                    Failure::text(Exit::Generic, &"the server certificate file is empty")
                })?
                .map_err(|error| Failure::text(Exit::Generic, &error))?;
            let provider = ring::default_provider();
            let tls = rustls::ClientConfig::builder_with_provider(Arc::new(provider.clone()))
                .with_safe_default_protocol_versions()
                .map_err(|error| Failure::text(Exit::Generic, &error))?
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(PinnedLeaf {
                    leaf: leaf.as_ref().to_vec(),
                    provider,
                }))
                .with_no_client_auth();
            let client = builder
                .use_preconfigured_tls(tls)
                .resolve(&host, loopback)
                .build()
                .map_err(|error| Failure::text(Exit::Generic, &error))?;
            (client, format!("https://{host}:{port}/healthz"))
        }
    } else {
        let client = builder
            .build()
            .map_err(|error| Failure::text(Exit::Generic, &error))?;
        (client, format!("http://{loopback}/healthz"))
    };
    let status = client
        .get(&url)
        .send()
        .await
        .map_err(|error| Failure::text(Exit::Generic, &error))?
        .status();
    if status == StatusCode::OK {
        Ok(())
    } else {
        Err(Failure::text(
            Exit::Generic,
            &format!("/healthz answered {status}"),
        ))
    }
}

/// Lowercase hexadecimal.
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        text.push(char::from(
            DIGITS
                .get(usize::from(byte >> 4_u8))
                .copied()
                .unwrap_or(b'0'),
        ));
        text.push(char::from(
            DIGITS
                .get(usize::from(byte & 0x0f))
                .copied()
                .unwrap_or(b'0'),
        ));
    }
    text
}

/// Trusts exactly one leaf certificate, byte for byte.
struct PinnedLeaf {
    /// DER of the configured server certificate.
    leaf: Vec<u8>,
    /// Ring algorithms verifying handshake signatures.
    provider: CryptoProvider,
}

impl fmt::Debug for PinnedLeaf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PinnedLeaf").finish_non_exhaustive()
    }
}

impl ServerCertVerifier for PinnedLeaf {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if end_entity.as_ref() == self.leaf.as_slice() {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}
