//! Optional observer of request outcomes and logins, used for self-metrics.

use core::{fmt, time::Duration};

use crate::RciError;

/// Receives one call per request and per login exchange of a client.
///
/// Implementations must be cheap and must not block: they run inline on the request path.
pub trait RciObserver: fmt::Debug + Send + Sync {
    /// One request finished (after its single 401 replay, if any).
    fn request(&self, outcome: RequestOutcome, elapsed: Duration);

    /// One login exchange finished; `scheme` is `None` when it failed before a scheme was
    /// chosen.
    fn authentication(&self, scheme: Option<LoginScheme>, success: bool);
}

/// Coarse request outcome, safe to use as a metric label.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RequestOutcome {
    /// A response was decoded.
    Ok,
    /// Authentication failed.
    Auth,
    /// Transport failure or timeout.
    Transport,
    /// Unexpected HTTP status, missing resource or unsupported method.
    Http,
    /// Any other failure (RCI status, size, decode, policy, validation).
    Other,
}

impl RequestOutcome {
    /// Classifies a request result.
    #[inline]
    #[must_use]
    pub const fn of<T>(result: &Result<T, RciError>) -> Self {
        match result {
            Ok(_) => Self::Ok,
            Err(RciError::Auth(_)) => Self::Auth,
            Err(RciError::Transport | RciError::Timeout | RciError::Cancelled) => Self::Transport,
            Err(RciError::Http { status: _ } | RciError::NotFound | RciError::MethodNotAllowed) => {
                Self::Http
            }
            Err(
                RciError::Rci {
                    pointer: _,
                    code: _,
                    ident: _,
                    message: _,
                }
                | RciError::BodyTooLarge
                | RciError::Decode
                | RciError::Policy
                | RciError::Validation,
            ) => Self::Other,
        }
    }

    /// Stable lowercase label value.
    #[inline]
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Auth => "auth_error",
            Self::Transport => "transport_error",
            Self::Http => "http_error",
            Self::Other => "error",
        }
    }
}

/// Challenge-response login scheme.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum LoginScheme {
    /// `x-ndw2-interactive`.
    Ndw2,
    /// `x-ndw4-interactive`.
    Ndw4,
    /// The challenge request already returned a valid session.
    Existing,
}

impl LoginScheme {
    /// Stable lowercase label value.
    #[inline]
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ndw2 => "ndw2",
            Self::Ndw4 => "ndw4",
            Self::Existing => "existing",
        }
    }
}
