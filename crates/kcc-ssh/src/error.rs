//! Errors of the SSH transport, the command grammars and the output parsers.
//!
//! No variant carries command output, a password, a private key or the refused
//! argument; a host key mismatch carries the two public fingerprints.

use core::fmt;

use thiserror::Error;

/// The bound that expired.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Phase {
    /// TCP connect and SSH handshake, host key check included.
    Connect,
    /// Authentication.
    Auth,
    /// A command that only reads.
    Read,
    /// A command that changes the router.
    Mutation,
}

impl fmt::Display for Phase {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Connect => "connect",
            Self::Auth => "authentication",
            Self::Read => "read",
            Self::Mutation => "mutation",
        })
    }
}

/// The grammar an argument failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Grammar {
    /// `^[a-z0-9][a-z0-9+._-]{0,63}$`.
    PackageName,
    /// `^S[0-9]{2}[A-Za-z0-9._-]{1,48}$`.
    ServiceName,
    /// 1 to 32 of `[a-z0-9-]`.
    RouterId,
    /// `ssh-ed25519 <base64>`.
    PublicKeyLine,
}

impl fmt::Display for Grammar {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::PackageName => "package name",
            Self::ServiceName => "service name",
            Self::RouterId => "router id",
            Self::PublicKeyLine => "public key line",
        })
    }
}

/// Every failure of this crate.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[non_exhaustive]
#[expect(
    clippy::module_name_repetitions,
    reason = "the error type is named SshError across the crates that use it"
)]
pub enum SshError {
    /// An argument does not match its grammar; nothing was sent.
    #[error("invalid {0}")]
    InvalidArgument(Grammar),
    /// The outbound policy admits no address of the router for SSH.
    #[error("no router address is admitted for SSH")]
    NotAdmitted,
    /// No admitted address accepted a TCP connection.
    #[error("SSH connection failed")]
    Connect,
    /// A bound expired; for a mutation the command may still run on the router.
    #[error("SSH {0} timed out")]
    Timeout(Phase),
    /// The server presented a host key or certificate that is not a plain ed25519 key.
    #[error("the SSH host key is not ed25519")]
    UnsupportedHostKey,
    /// The server's ed25519 host key differs from the pin; nothing was authenticated.
    #[error("SSH host key changed: pinned {expected}, presented {actual}")]
    HostKeyMismatch {
        /// SHA-256 fingerprint of the pinned key.
        expected: String,
        /// SHA-256 fingerprint of the presented key.
        actual: String,
    },
    /// A private key or pinned host key text that does not parse as ed25519.
    #[error("invalid SSH key")]
    InvalidKey,
    /// The server refused the password or key.
    #[error("SSH authentication rejected")]
    AuthRejected,
    /// The SSH protocol failed.
    #[error("SSH protocol error")]
    Protocol,
    /// The connection ended.
    #[error("SSH connection lost")]
    Disconnected,
    /// The command printed more than the output limit; the channel was closed.
    #[error("command output exceeds the limit")]
    OutputTruncated,
    /// The channel closed without an exit status.
    #[error("command ended without an exit status")]
    NoExitStatus,
    /// `rc.func` refused to start a disabled service (exit 8).
    #[error("the service is disabled")]
    ServiceDisabled,
    /// `rc.func` reported the action failed (exit 255).
    #[error("the service action failed")]
    ServiceFailed,
    /// An exit status or output outside the known shapes.
    #[error("unexpected command output")]
    UnexpectedOutput,
}
