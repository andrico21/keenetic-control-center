//! The health check of a new generation: `/healthz` at the address it bound (over TLS
//! trusting exactly the configured certificate) and, for a main generation with metrics,
//! `/metrics` on the metrics listener.

extern crate alloc;

use alloc::sync::Arc;
use core::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};
use std::{
    io::{self, BufRead as _, BufReader, Read, Write},
    net::TcpStream,
    thread,
    time::Instant,
};

use rustls::{ClientConfig, ClientConnection, StreamOwned, crypto::ring, pki_types::ServerName};

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
}

impl Probe {
    /// Probes TLS with `tls` pinned, and `metrics` when set.
    pub(crate) const fn new(tls: Option<Vec<u8>>, metrics: Option<SocketAddr>) -> Self {
        Self { tls, metrics }
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
                self.tls.as_deref(),
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

/// One `GET path` with `Host: localhost` at `address`; succeeds on status 200 only.
fn get(address: SocketAddr, path: &str, tls: Option<&[u8]>, deadline: Instant) -> io::Result<()> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|left| !left.is_zero())
        .ok_or_else(|| io::Error::from(io::ErrorKind::TimedOut))?;
    let stream = TcpStream::connect_timeout(&address, remaining)?;
    stream.set_read_timeout(Some(remaining))?;
    stream.set_write_timeout(Some(remaining))?;
    let request = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    let status = match tls {
        Some(leaf) => {
            let connection = ClientConnection::new(
                pinned(leaf)?,
                ServerName::try_from("localhost").map_err(io::Error::other)?,
            )
            .map_err(io::Error::other)?;
            exchange(StreamOwned::new(connection, stream), &request)?
        }
        None => exchange(stream, &request)?,
    };
    if status.split_whitespace().nth(1) == Some("200") {
        Ok(())
    } else {
        Err(io::Error::other(format!("answered {}", status.trim_end())))
    }
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

/// A TLS client that trusts exactly `leaf` and presents no certificate.
fn pinned(leaf: &[u8]) -> io::Result<Arc<ClientConfig>> {
    Ok(Arc::new(
        ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(io::Error::other)?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedLeaf::new(leaf.to_vec())))
            .with_no_client_auth(),
    ))
}
