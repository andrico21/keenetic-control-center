//! Typed, value-free causes of failed router requests.
//!
//! Every text here names a cause class only: no URL, host, port, query, header, cookie,
//! login or router-provided value ever enters a cause.

pub mod answer;
pub mod collapse;

use core::{error::Error as StdError, fmt};
use std::io;

use rustls::CertificateError;

/// Deepest error chain [`classify`] walks.
const CHAIN_LIMIT: usize = 32;

/// Why a request failed before a usable HTTP answer arrived.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum TransportCause {
    /// The router refused the TCP connection.
    ConnectRefused,
    /// The connection was reset or aborted.
    ConnectReset,
    /// The operating system gave up connecting.
    ConnectTimeout,
    /// Connecting failed for another reason.
    ConnectOther,
    /// The router's name could not be resolved.
    Dns,
    /// The TLS layer failed.
    Tls(TlsCause),
    /// The router closed the connection after the request, before any answer.
    ClosedBeforeAnswer,
    /// The answer body stopped before its end.
    BodyInterrupted,
    /// The answer was not valid HTTP.
    Protocol,
    /// The router answered with a redirect.
    Redirect,
    /// kcc itself could not send the request.
    Local(LocalCause),
}

/// Why the TLS layer failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum TlsCause {
    /// The certificate chain ends at an unknown issuer.
    UnknownIssuer,
    /// The certificate names another host.
    NameMismatch,
    /// The certificate has expired.
    Expired,
    /// The certificate was rejected for another reason.
    OtherCertificate,
    /// The handshake failed before or apart from the certificate check.
    Handshake,
}

/// A failure inside kcc before or while sending a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum LocalCause {
    /// The random source failed.
    Random,
    /// The router's request budget was closed.
    Budget,
    /// A header value could not be built.
    Header,
    /// The request body could not be serialized.
    Serialize,
    /// The HTTP client or its TLS provider could not be built.
    ClientBuild,
    /// A background worker stopped.
    Worker,
    /// The request body could not be copied for a retry.
    BodyClone,
}

impl TransportCause {
    /// Stable snake-case label of the cause, for log fields.
    #[inline]
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::ConnectRefused => "connect_refused",
            Self::ConnectReset => "connect_reset",
            Self::ConnectTimeout => "connect_timeout",
            Self::ConnectOther => "connect_other",
            Self::Dns => "dns",
            Self::Tls(TlsCause::UnknownIssuer) => "tls_unknown_issuer",
            Self::Tls(TlsCause::NameMismatch) => "tls_name_mismatch",
            Self::Tls(TlsCause::Expired) => "tls_expired",
            Self::Tls(TlsCause::OtherCertificate) => "tls_certificate",
            Self::Tls(TlsCause::Handshake) => "tls_handshake",
            Self::ClosedBeforeAnswer => "closed_before_answer",
            Self::BodyInterrupted => "body_interrupted",
            Self::Protocol => "protocol",
            Self::Redirect => "redirect",
            Self::Local(LocalCause::Random) => "local_random",
            Self::Local(LocalCause::Budget) => "local_budget",
            Self::Local(LocalCause::Header) => "local_header",
            Self::Local(LocalCause::Serialize) => "local_serialize",
            Self::Local(LocalCause::ClientBuild) => "local_client_build",
            Self::Local(LocalCause::Worker) => "local_worker",
            Self::Local(LocalCause::BodyClone) => "local_body_clone",
        }
    }
}

impl fmt::Display for TransportCause {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ConnectRefused => "connection refused",
            Self::ConnectReset => "connection reset",
            Self::ConnectTimeout => "connection timed out",
            Self::ConnectOther => "could not connect",
            Self::Dns => "name resolution failed",
            Self::Tls(TlsCause::UnknownIssuer) => "TLS certificate from an unknown issuer",
            Self::Tls(TlsCause::NameMismatch) => "TLS certificate for another name",
            Self::Tls(TlsCause::Expired) => "TLS certificate expired",
            Self::Tls(TlsCause::OtherCertificate) => "TLS certificate rejected",
            Self::Tls(TlsCause::Handshake) => "TLS handshake failed",
            Self::ClosedBeforeAnswer => "the router closed the connection before answering",
            Self::BodyInterrupted => "the answer was cut off",
            Self::Protocol => "the answer was not valid HTTP",
            Self::Redirect => "the router answered with a redirect",
            Self::Local(LocalCause::Random) => "local error: random source",
            Self::Local(LocalCause::Budget) => "local error: request budget closed",
            Self::Local(LocalCause::Header) => "local error: header value",
            Self::Local(LocalCause::Serialize) => "local error: request body",
            Self::Local(LocalCause::ClientBuild) => "local error: HTTP client setup",
            Self::Local(LocalCause::Worker) => "local error: worker stopped",
            Self::Local(LocalCause::BodyClone) => "local error: request body copy",
        })
    }
}

/// The first cause of each layer found in an error chain.
#[derive(Default)]
struct Found {
    /// The first TLS failure.
    tls: Option<TlsCause>,
    /// The first operating-system failure of a known kind.
    io: Option<TransportCause>,
    /// The first HTTP-layer failure of a known kind.
    hyper: Option<TransportCause>,
}

/// Classifies a non-timeout reqwest failure without formatting it, its URL or its sources.
///
/// The chain is walked through `source()` and into every `io::Error`'s wrapped error, where
/// rustls keeps its failures. A TLS failure wins, then the operating system's error kind,
/// then hyper's, then reqwest's own flags.
#[inline]
#[must_use]
pub fn classify(error: &reqwest::Error) -> TransportCause {
    let mut found = Found::default();
    let mut pending: Vec<&(dyn StdError + 'static)> = error.source().into_iter().collect();
    let mut visited = 0_usize;
    while let Some(current) = pending.pop()
        && visited < CHAIN_LIMIT
    {
        visited = visited.saturating_add(1);
        inspect(current, &mut found);
        if let Some(next) = current.source() {
            pending.push(next);
        }
        if let Some(wrapped) = current
            .downcast_ref::<io::Error>()
            .and_then(io::Error::get_ref)
        {
            pending.push(wrapped);
        }
    }
    if let Some(tls) = found.tls {
        return TransportCause::Tls(tls);
    }
    found.io.or(found.hyper).unwrap_or_else(|| flagged(error))
}

/// Records the cause `error` names, keeping the first one of each layer.
fn inspect(error: &(dyn StdError + 'static), found: &mut Found) {
    if let Some(tls) = error.downcast_ref::<rustls::Error>() {
        found.tls = found.tls.or_else(|| Some(tls_cause(tls)));
    } else if let Some(io_error) = error.downcast_ref::<io::Error>() {
        found.io = found.io.or_else(|| io_cause(io_error.kind()));
    } else if let Some(hyper_error) = error.downcast_ref::<hyper::Error>() {
        found.hyper = found.hyper.or_else(|| {
            if hyper_error.is_incomplete_message() {
                Some(TransportCause::ClosedBeforeAnswer)
            } else if hyper_error.is_parse() {
                Some(TransportCause::Protocol)
            } else if hyper_error.is_body_write_aborted() || hyper_error.is_closed() {
                Some(TransportCause::ConnectReset)
            } else {
                None
            }
        });
    } else {
        // Other layers carry no cause of their own; their sources are walked.
    }
}

/// The cause an operating-system error of `kind` names, if any.
fn io_cause(kind: io::ErrorKind) -> Option<TransportCause> {
    if kind == io::ErrorKind::ConnectionRefused {
        Some(TransportCause::ConnectRefused)
    } else if matches!(
        kind,
        io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::UnexpectedEof
    ) {
        Some(TransportCause::ConnectReset)
    } else if kind == io::ErrorKind::TimedOut {
        Some(TransportCause::ConnectTimeout)
    } else {
        None
    }
}

/// The TLS cause of a rustls failure.
const fn tls_cause(error: &rustls::Error) -> TlsCause {
    let rustls::Error::InvalidCertificate(certificate) = error else {
        return TlsCause::Handshake;
    };
    if matches!(certificate, CertificateError::UnknownIssuer) {
        TlsCause::UnknownIssuer
    } else if matches!(
        certificate,
        CertificateError::NotValidForName
            | CertificateError::NotValidForNameContext {
                expected: _,
                presented: _,
            }
    ) {
        TlsCause::NameMismatch
    } else if matches!(
        certificate,
        CertificateError::Expired
            | CertificateError::ExpiredContext {
                time: _,
                not_after: _,
            }
    ) {
        TlsCause::Expired
    } else {
        TlsCause::OtherCertificate
    }
}

/// The cause reqwest's own flags name when the chain names none.
fn flagged(error: &reqwest::Error) -> TransportCause {
    if error.is_redirect() {
        TransportCause::Redirect
    } else if error.is_body() || error.is_decode() {
        TransportCause::BodyInterrupted
    } else if error.is_builder() {
        TransportCause::Local(LocalCause::ClientBuild)
    } else {
        // `is_connect` and every other flag: the connection could not be used.
        TransportCause::ConnectOther
    }
}
