//! The health check of a new generation: `/healthz` at the address it bound (over TLS
//! trusting exactly the configured certificate) and, for a main generation with metrics,
//! `/metrics` on the metrics listener.
//!
//! Over TLS the probe presents no client certificate and records whether the listener
//! asked for one, which must match its client-certificate sign-in: never asked when it is
//! off; asked and answered when it is optional; asked and refused with the
//! `certificate_required` (or `handshake_failure`) alert when it is required, so a listener
//! that does not enforce a required certificate fails the check. A required listener's
//! `/healthz` cannot be reached without a certificate kcc does not hold; the refusal comes
//! from the TLS acceptor of the same kit server, after it presented the pinned
//! certificate.

extern crate alloc;

use alloc::sync::Arc;
use core::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
use std::{
    io::{self, BufRead as _, BufReader, Read, Write},
    net::TcpStream,
    thread,
    time::Instant,
};

use kcc_app::settings::mcp_schema::MtlsMode;
use rustls::{
    AlertDescription, ClientConfig, ClientConnection, SignatureScheme, StreamOwned,
    client::ResolvesClientCert, crypto::ring, pki_types::ServerName, sign::CertifiedKey,
};

use crate::cli::tls::PinnedLeaf;

/// The pause between two probes of a listener that did not answer yet.
const RETRY: Duration = Duration::from_millis(100);

/// What a generation's health check probes.
#[derive(Debug, Clone)]
pub(crate) struct Probe {
    /// DER of the listener's configured certificate, when it serves TLS.
    tls: Option<Vec<u8>>,
    /// The metrics listener of a main generation.
    metrics: Option<SocketAddr>,
    /// The listener's client-certificate sign-in.
    mtls: MtlsMode,
}

impl Probe {
    /// Probes TLS with `tls` pinned, and `metrics` when set; no client-certificate sign-in.
    pub(crate) const fn new(tls: Option<Vec<u8>>, metrics: Option<SocketAddr>) -> Self {
        Self {
            tls,
            metrics,
            mtls: MtlsMode::Off,
        }
    }

    /// The same probe of a listener whose client-certificate sign-in is `mtls`.
    pub(crate) const fn with_mtls(mut self, mtls: MtlsMode) -> Self {
        self.mtls = mtls;
        self
    }

    /// Probes the generation bound at `address` until each probe answers 200, for at most
    /// `window`; blocking.
    ///
    /// # Errors
    ///
    /// The last failure of the probe that did not pass in time.
    // cancel-safe: synchronous.
    pub(crate) fn check(&self, address: SocketAddr, window: Duration) -> Result<(), String> {
        let deadline = Instant::now()
            .checked_add(window)
            .ok_or_else(|| "health window overflows the clock".to_owned())?;
        until_ok(deadline, || {
            get(
                reachable(address),
                "/healthz",
                self.tls.as_deref().map(|leaf| (leaf, self.mtls)),
                deadline,
            )
        })
        .map_err(|error| format!("/healthz: {error}"))?;
        if let Some(metrics) = self.metrics {
            until_ok(deadline, || {
                get(reachable(metrics), "/metrics", None, deadline)
            })
            .map_err(|error| format!("/metrics: {error}"))?;
        }
        Ok(())
    }
}

/// Runs `probe` until it passes or `deadline` passes.
fn until_ok<F>(deadline: Instant, mut probe: F) -> io::Result<()>
where
    F: FnMut() -> io::Result<()>,
{
    loop {
        let error = match probe() {
            Ok(()) => return Ok(()),
            Err(error) => error,
        };
        if Instant::now()
            .checked_add(RETRY)
            .is_none_or(|next| next >= deadline)
        {
            return Err(error);
        }
        thread::sleep(RETRY);
    }
}

/// `address`, with an unspecified IP replaced by loopback of the same family.
const fn reachable(address: SocketAddr) -> SocketAddr {
    if !address.ip().is_unspecified() {
        return address;
    }
    let loopback = match address.ip() {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::LOCALHOST),
    };
    SocketAddr::new(loopback, address.port())
}

/// One `GET path` with `Host: localhost` at `address`, over TLS pinned to the leaf of
/// `tls` when set; succeeds on status 200 only, or as [`judged`] says over TLS.
fn get(
    address: SocketAddr,
    path: &str,
    tls: Option<(&[u8], MtlsMode)>,
    deadline: Instant,
) -> io::Result<()> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|left| !left.is_zero())
        .ok_or_else(|| io::Error::from(io::ErrorKind::TimedOut))?;
    let stream = TcpStream::connect_timeout(&address, remaining)?;
    stream.set_read_timeout(Some(remaining))?;
    stream.set_write_timeout(Some(remaining))?;
    let request = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    let Some((leaf, mtls)) = tls else {
        return ok(&exchange(stream, &request)?);
    };
    let asked = Arc::new(Asked::default());
    let connection = ClientConnection::new(
        pinned(leaf, Arc::clone(&asked))?,
        ServerName::try_from("localhost").map_err(io::Error::other)?,
    )
    .map_err(io::Error::other)?;
    let answered = exchange(StreamOwned::new(connection, stream), &request);
    judged(mtls, asked.0.load(Ordering::SeqCst), answered)
}

/// Succeeds when `status` is a 200 status line.
fn ok(status: &str) -> io::Result<()> {
    if status.split_whitespace().nth(1) == Some("200") {
        Ok(())
    } else {
        Err(io::Error::other(format!("answered {}", status.trim_end())))
    }
}

/// Whether a TLS exchange that `answered` passes for a listener whose client-certificate
/// sign-in is `mtls`, given whether it `asked` for a certificate.
fn judged(mtls: MtlsMode, asked: bool, answered: io::Result<String>) -> io::Result<()> {
    let expected = match mtls {
        MtlsMode::Required => {
            if !asked {
                return Err(io::Error::other(
                    "did not ask for the required client certificate",
                ));
            }
            return match answered {
                Ok(status) => Err(io::Error::other(format!(
                    "answered {} without the required client certificate",
                    status.trim_end()
                ))),
                Err(error) if refused_certificate(&error) => Ok(()),
                Err(error) => Err(error),
            };
        }
        MtlsMode::Optional => true,
        MtlsMode::Off | _ => false,
    };
    let status = answered?;
    if asked != expected {
        return Err(io::Error::other(if asked {
            "asked for a client certificate while client certificates are off"
        } else {
            "did not ask for the optional client certificate"
        }));
    }
    ok(&status)
}

/// Whether `error` is the alert a server sends when a required client certificate is
/// missing.
fn refused_certificate(error: &io::Error) -> bool {
    matches!(
        error
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<rustls::Error>()),
        Some(rustls::Error::AlertReceived(
            AlertDescription::CertificateRequired | AlertDescription::HandshakeFailure
        ))
    )
}

/// Writes `request` and reads the status line.
fn exchange<S>(mut stream: S, request: &str) -> io::Result<String>
where
    S: Read + Write,
{
    stream.write_all(request.as_bytes())?;
    stream.flush()?;
    let mut status = String::new();
    let _: usize = BufReader::new(stream).read_line(&mut status)?;
    Ok(status)
}

/// A TLS client that trusts exactly `leaf` and presents no certificate, noting in `asked`
/// whether the server asked for one.
fn pinned(leaf: &[u8], asked: Arc<Asked>) -> io::Result<Arc<ClientConfig>> {
    Ok(Arc::new(
        ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(io::Error::other)?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedLeaf::new(leaf.to_vec())))
            .with_client_cert_resolver(asked),
    ))
}

/// Notes whether the server asked for a client certificate, and offers none.
#[derive(Debug, Default)]
struct Asked(AtomicBool);

impl ResolvesClientCert for Asked {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        self.0.store(true, Ordering::SeqCst);
        None
    }

    fn has_certs(&self) -> bool {
        true
    }
}
