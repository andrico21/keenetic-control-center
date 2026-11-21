//! Admitted addresses, pinned targets, timeouts and the russh handshake.

use alloc::sync::Arc;
use core::{net::SocketAddr, time::Duration};

use kcc_rci::{OutboundPolicy, RouterUrl};
use russh::{
    Preferred,
    client::{self, Handle},
    keys::{Algorithm, PrivateKeyWithHashAlg, PublicKeyOrCertificate},
};
use secrecy::ExposeSecret as _;
use tokio::{net::TcpStream, sync::oneshot, time::timeout};

use crate::{
    error::{Phase, SshError},
    keys::{Auth, HostKeyPin, private_key},
};

/// The only login of Entware's dropbear.
const USER: &str = "root";

/// The only host key algorithm offered.
const HOST_KEY_ALGORITHMS: &[Algorithm] = &[Algorithm::Ed25519];

/// Interval of keepalive requests while the server is silent.
const KEEPALIVE: Duration = Duration::from_secs(15);

/// A connection idle this long is closed.
const INACTIVITY: Duration = Duration::from_secs(60);

/// Addresses of one router that the outbound policy admits for SSH, with the SSH port.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct AdmittedAddresses(Vec<SocketAddr>);

impl AdmittedAddresses {
    /// Resolves `router`'s host and keeps the addresses `policy` admits for SSH on `port`
    /// (`OutboundPolicy::admit_ssh`).
    ///
    /// # Errors
    ///
    /// Returns [`SshError::NotAdmitted`] when no address is admitted or resolution fails.
    // cancel-safe: dropped, it abandons a DNS lookup; nothing is dialled.
    #[inline]
    pub async fn admit(
        policy: &OutboundPolicy,
        router: &RouterUrl,
        port: u16,
    ) -> Result<Self, SshError> {
        match policy.admit_ssh(router, port).await {
            Ok(addresses) => Ok(Self(addresses)),
            Err(error) => {
                tracing::debug!(%error, "no SSH address admitted");
                Err(SshError::NotAdmitted)
            }
        }
    }

    /// The addresses, in resolver order.
    #[inline]
    #[must_use]
    pub fn as_slice(&self) -> &[SocketAddr] {
        &self.0
    }
}

/// Where a session connects: admitted addresses and the host key they must present.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct PinnedTarget {
    /// Admitted addresses; each carries the router's SSH port.
    pub addresses: AdmittedAddresses,
    /// The host key the server must present.
    pub pin: HostKeyPin,
}

impl PinnedTarget {
    /// A target of `addresses` pinned to `pin`.
    #[inline]
    #[must_use]
    pub const fn new(addresses: AdmittedAddresses, pin: HostKeyPin) -> Self {
        Self { addresses, pin }
    }
}

/// Bounds of the connection phases and of one command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Timeouts {
    /// TCP connect and handshake (default 5 s).
    pub connect: Duration,
    /// Authentication (default 10 s).
    pub auth: Duration,
    /// A reading command, from exec to channel close (default 30 s).
    pub read: Duration,
    /// A mutating command, from exec to channel close (default 600 s).
    pub mutation: Duration,
}

impl Default for Timeouts {
    #[inline]
    fn default() -> Self {
        Self {
            connect: Duration::from_secs(5),
            auth: Duration::from_secs(10),
            read: Duration::from_secs(30),
            mutation: Duration::from_secs(600),
        }
    }
}

/// What the handshake does with the presented host key.
enum Check {
    /// Hand the key out and accept it, for a probe that never authenticates.
    Probe(Option<oneshot::Sender<HostKeyPin>>),
    /// Accept only a key equal to the pin.
    Pinned(HostKeyPin),
}

/// The russh client handler: checks the host key.
pub(crate) struct Verifier {
    /// The check to apply.
    check: Check,
}

/// What the handler reports to russh.
#[derive(Debug)]
pub(crate) enum HandlerError {
    /// A russh failure.
    Ssh(russh::Error),
    /// The host key was refused.
    Refused(SshError),
}

impl From<russh::Error> for HandlerError {
    #[inline]
    fn from(error: russh::Error) -> Self {
        Self::Ssh(error)
    }
}

impl client::Handler for Verifier {
    type Error = HandlerError;

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "async is mandated by the russh handler trait"
    )]
    // cancel-safe: it has no await point.
    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let PublicKeyOrCertificate::PublicKey {
            key,
            hash_alg: _plain_key,
        } = server_public_key
        else {
            return Err(HandlerError::Refused(SshError::UnsupportedHostKey));
        };
        let presented = HostKeyPin::from_key(key).map_err(HandlerError::Refused)?;
        match &mut self.check {
            Check::Pinned(expected) if *expected == presented => Ok(true),
            Check::Pinned(expected) => {
                let mismatch = SshError::HostKeyMismatch {
                    expected: expected.fingerprint(),
                    actual: presented.fingerprint(),
                };
                tracing::warn!(error = %mismatch, "SSH host key refused");
                Err(HandlerError::Refused(mismatch))
            }
            Check::Probe(slot) => {
                if let Some(sender) = slot.take() {
                    match sender.send(presented) {
                        Ok(()) | Err(_) => {}
                    }
                }
                Ok(true)
            }
        }
    }
}

/// Maps a russh failure; its text is logged at debug level and never carried.
pub(crate) fn from_russh(error: &russh::Error) -> SshError {
    tracing::debug!(%error, "SSH failure");
    if matches!(
        error,
        russh::Error::Disconnect
            | russh::Error::HUP
            | russh::Error::IO(_)
            | russh::Error::SendError
            | russh::Error::RecvError
            | russh::Error::KeepaliveTimeout
            | russh::Error::InactivityTimeout
            | russh::Error::ConnectionTimeout
    ) {
        SshError::Disconnected
    } else {
        SshError::Protocol
    }
}

/// Maps a handler failure.
fn from_handler(failure: HandlerError) -> SshError {
    match failure {
        HandlerError::Ssh(error) => from_russh(&error),
        HandlerError::Refused(error) => error,
    }
}

/// The client configuration: ed25519 host keys only, keepalive and inactivity bounds.
fn config() -> client::Config {
    client::Config {
        preferred: Preferred {
            key: HOST_KEY_ALGORITHMS.into(),
            ..Preferred::DEFAULT
        },
        keepalive_interval: Some(KEEPALIVE),
        inactivity_timeout: Some(INACTIVITY),
        nodelay: true,
        ..client::Config::default()
    }
}

/// Dials the addresses in order and runs the handshake on the first that answers.
///
/// # Errors
///
/// Returns [`SshError::Connect`] when no address answers and the handshake's errors.
// cancel-safe: dropped, the connection is closed; nothing was authenticated or sent.
async fn open(addresses: &[SocketAddr], check: Check) -> Result<Handle<Verifier>, SshError> {
    for address in addresses {
        match TcpStream::connect(address).await {
            Ok(stream) => {
                return client::connect_stream(Arc::new(config()), stream, Verifier { check })
                    .await
                    .map_err(from_handler);
            }
            Err(error) => tracing::debug!(%address, %error, "SSH TCP connect failed"),
        }
    }
    Err(SshError::Connect)
}

/// Connects without authenticating and returns the presented ed25519 host key.
///
/// # Errors
///
/// Returns [`SshError::Timeout`] after `timeouts.connect` and the handshake's errors.
// cancel-safe: dropped, the connection is closed; nothing was authenticated or sent.
pub(crate) async fn probe(
    addresses: &AdmittedAddresses,
    timeouts: Timeouts,
) -> Result<HostKeyPin, SshError> {
    let (sender, mut receiver) = oneshot::channel();
    let handle = timeout(
        timeouts.connect,
        open(addresses.as_slice(), Check::Probe(Some(sender))),
    )
    .await
    .map_err(|_elapsed| SshError::Timeout(Phase::Connect))??;
    drop(handle);
    receiver.try_recv().map_err(|_missing| SshError::Protocol)
}

/// Connects to `target`, refusing any host key but the pin, and authenticates as root.
///
/// # Errors
///
/// Returns [`SshError::Timeout`] after either bound and the handshake's and
/// authentication's errors.
// cancel-safe: dropped, the connection is closed; no command was sent.
pub(crate) async fn connect(
    target: PinnedTarget,
    auth: &Auth,
    timeouts: Timeouts,
) -> Result<Handle<Verifier>, SshError> {
    let mut handle = timeout(
        timeouts.connect,
        open(target.addresses.as_slice(), Check::Pinned(target.pin)),
    )
    .await
    .map_err(|_elapsed| SshError::Timeout(Phase::Connect))??;
    timeout(timeouts.auth, authenticate(&mut handle, auth))
        .await
        .map_err(|_elapsed| SshError::Timeout(Phase::Auth))??;
    Ok(handle)
}

/// Authenticates as root; the secret is exposed only at the russh call.
///
/// # Errors
///
/// Returns [`SshError::AuthRejected`], [`SshError::InvalidKey`] or a connection error.
// cancel-safe: dropped, the authentication request is abandoned with the connection.
async fn authenticate(handle: &mut Handle<Verifier>, auth: &Auth) -> Result<(), SshError> {
    let result = match auth {
        Auth::Password(password) => {
            handle
                .authenticate_password(USER, password.expose_secret())
                .await
        }
        Auth::Key(text) => {
            let key = PrivateKeyWithHashAlg::new(Arc::new(private_key(text)?), None);
            handle.authenticate_publickey(USER, key).await
        }
    }
    .map_err(|error| from_russh(&error))?;
    result.success().then_some(()).ok_or(SshError::AuthRejected)
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use russh::keys::Algorithm;

    use super::config;

    /// Todo 7: the client offers ssh-ed25519 as its only host key algorithm.
    #[test]
    fn only_ed25519_host_keys_are_offered() {
        assert_eq!(config().preferred.key.as_ref(), [Algorithm::Ed25519]);
    }
}
