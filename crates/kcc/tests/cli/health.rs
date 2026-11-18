//! `kcc healthcheck` against a running `kcc serve`, over TLS and plain HTTP.

use core::{error::Error, fmt::Write as _, time::Duration};
use std::{path::Path, process::Child, sync::mpsc};

use fluent_bundle::FluentArgs;
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use rustls::pki_types::{CertificateDer, pem::PemObject as _};
use sha2::{Digest as _, Sha256};

use super::{
    serve_port::{Start, await_ready, start_on_free_ports, stderr_lines},
    spawning,
    support::{Env, TestResult},
};

/// Longest wait for the server to listen.
const START_TIMEOUT: Duration = Duration::from_secs(30);

/// A running `kcc serve`, killed on drop.
struct Server {
    /// The process.
    child: Child,
    /// Its stderr lines, kept open so that its logging never fails.
    _lines: mpsc::Receiver<String>,
}

impl Drop for Server {
    fn drop(&mut self) {
        drop(self.child.kill());
        drop(self.child.wait());
    }
}

/// Writes `config(port)` as the configuration body for a free `port`, starts `kcc serve`
/// and returns once it logged that it listens.
fn serve<F>(env: &Env, config: F) -> Result<(u16, Server), Box<dyn Error>>
where
    F: Fn(u16) -> String,
{
    let config_path = env.path("kcc.toml");
    let path = config_path.to_str().ok_or("non-UTF-8 path")?;
    let ([port], server) = start_on_free_ports(|[port]| -> TestResult<Start<Server>> {
        env.write_config(&config(port))?;
        let mut child = spawning::spawn(&mut env.command(&["--config", path, "serve"]))?;
        let lines = stderr_lines(&mut child)?;
        let started = await_ready(&lines, |line| line.contains("listening"), START_TIMEOUT)?;
        let server = Server {
            child,
            _lines: lines,
        };
        Ok(match started {
            Start::Ready(_seen) => Start::Ready(server),
            Start::AddressInUse => Start::AddressInUse,
        })
    })?;
    Ok((port, server))
}

/// The `[server]` table on `port`, with listener TLS when `tls` names the PEM files.
fn server_table(port: u16, tls: Option<(&str, &str)>) -> String {
    let listener = format!("[server]\nlisten_addr = \"127.0.0.1\"\nlisten_port = {port}\n");
    match tls {
        Some((cert, key)) => {
            format!("{listener}tls_cert_path = {cert:?}\ntls_key_path = {key:?}\n")
        }
        None => listener,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn healthcheck_over_plain_http_on_loopback() -> TestResult {
    let env = Env::new("")?;
    let (_port, server) = serve(&env, |port| server_table(port, None))?;
    let up = env.kcc(&["healthcheck"])?;
    assert_eq!(up.code, 0_i32, "{up:?}");
    drop(server);
    let down = env.kcc(&["healthcheck"])?;
    assert_eq!(down.code, 1_i32, "nothing listens any more: {down:?}");
    Ok(())
}

/// The lowercase hex SHA-256 of the certificate in the PEM file at `path`.
fn fingerprint(path: &Path) -> Result<String, Box<dyn Error>> {
    let der = CertificateDer::from_pem_file(path)?;
    let mut hex = String::new();
    for byte in Sha256::digest(der.as_ref()) {
        write!(hex, "{byte:02x}")?;
    }
    Ok(hex)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn healthcheck_over_tls_trusts_exactly_the_configured_certificate() -> TestResult {
    let env = Env::new("")?;
    let certs = env.path("certs");
    let other = env.path("other");
    for dir in [&certs, &other] {
        let made = env.kcc_bare(&[
            "tls",
            "self-signed",
            "--host",
            "localhost",
            "--out-dir",
            dir.to_str().ok_or("non-UTF-8 path")?,
        ])?;
        assert_eq!(made.code, 0_i32, "{made:?}");
        let cert = dir.join("kcc-cert.pem");
        let mut args = FluentArgs::new();
        args.set("path", cert.display().to_string());
        args.set("value", fingerprint(&cert)?);
        assert_eq!(
            made.stdout.trim_end(),
            tr(Locale::En, keys::CLI_TLS_WRITTEN, Some(&args)),
            "the report names the written certificate and its fingerprint"
        );
    }
    let cert = certs.join("kcc-cert.pem");
    let key = certs.join("kcc-key.pem");
    let cert_text = cert.to_str().ok_or("non-UTF-8 path")?;
    let key_text = key.to_str().ok_or("non-UTF-8 path")?;
    let (port, _server) = serve(&env, |port| server_table(port, Some((cert_text, key_text))))?;
    let up = env.kcc(&["healthcheck"])?;
    assert_eq!(up.code, 0_i32, "{up:?}");
    let other_cert = other.join("kcc-cert.pem");
    let pinned_elsewhere = server_table(
        port,
        Some((other_cert.to_str().ok_or("non-UTF-8 path")?, key_text)),
    );
    let wrong = Env::new(&pinned_elsewhere)?;
    let refused = wrong.kcc(&["healthcheck"])?;
    assert_eq!(
        refused.code, 1_i32,
        "another certificate must not be trusted: {refused:?}"
    );
    Ok(())
}
