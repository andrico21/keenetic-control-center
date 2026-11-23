//! The internal JWKS listener the kit validates kcc's tokens with.
//!
//! Plain HTTP on one port of both loopback addresses (`localhost` resolves to both),
//! `GET /jwks` only, started once for the process. Holding the same port on `127.0.0.1`
//! and on `[::1]` leaves no loopback address on which another local process could answer
//! the kit's key fetch. Where `IPv6` loopback exists but the port is taken there, another
//! port is tried, at most [`ATTEMPTS`] times; without it `127.0.0.1` alone is bound.

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::{io, net::TcpListener};

/// Ports tried before kcc sign-in is refused.
pub(crate) const ATTEMPTS: usize = 5;

/// Why no JWKS listener could be bound.
#[derive(Debug, thiserror::Error)]
pub(crate) enum JwksError {
    /// Every port tried was taken on `127.0.0.1` or on `[::1]`.
    #[error("no port was free on both 127.0.0.1 and [::1] after {ATTEMPTS} attempts")]
    Taken,
    /// A bind failed otherwise.
    #[error("the internal JWKS listener cannot bind: {0}")]
    Bind(#[from] io::Error),
}

/// The bound listeners: one port, every loopback address there is.
#[derive(Debug)]
pub(crate) struct Bound {
    /// The port.
    port: u16,
    /// `127.0.0.1`, then `[::1]` where `IPv6` loopback exists.
    listeners: Vec<TcpListener>,
}

impl Bound {
    /// The port.
    pub(crate) const fn port(&self) -> u16 {
        self.port
    }

    /// The listeners, `127.0.0.1` first.
    pub(crate) fn into_listeners(self) -> Vec<TcpListener> {
        self.listeners
    }
}

/// Binds the JWKS listener on the first port of `candidates` free on both loopback
/// addresses (`0`: a port the operating system chooses on 127.0.0.1), trying at most
/// [`ATTEMPTS`] of them.
///
/// # Errors
///
/// [`JwksError::Taken`] when every port tried was taken; [`JwksError::Bind`] for another
/// bind failure.
pub(crate) fn bind<I>(candidates: I) -> Result<Bound, JwksError>
where
    I: IntoIterator<Item = u16>,
{
    let ipv6 = TcpListener::bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0)).is_ok();
    for candidate in candidates.into_iter().take(ATTEMPTS) {
        let v4 =
            match TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), candidate)) {
                Ok(listener) => listener,
                Err(error) if error.kind() == io::ErrorKind::AddrInUse => continue,
                Err(error) => return Err(JwksError::Bind(error)),
            };
        let port = v4.local_addr()?.port();
        if !ipv6 {
            return Ok(Bound {
                port,
                listeners: vec![v4],
            });
        }
        match TcpListener::bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port)) {
            Ok(v6) => {
                return Ok(Bound {
                    port,
                    listeners: vec![v4, v6],
                });
            }
            Err(error) if error.kind() == io::ErrorKind::AddrInUse => {}
            Err(error) => return Err(JwksError::Bind(error)),
        }
    }
    Err(JwksError::Taken)
}
