//! Delivery failures, and how a Bot API reply or a transport error maps to them.
//!
//! No variant carries a URL, a request or a reply body: the bot token is part of the
//! request URL, so every [`reqwest::Error`] is stripped with
//! [`reqwest::Error::without_url`] and then reduced to a variant.

use core::{error::Error as StdError, time::Duration};

use kcc_app::notify_store::DisabledReason;
use reqwest::StatusCode;
use serde::Deserialize;

use super::dns::AddressRefused;

/// Wait after a 429 reply that names no `retry_after`.
const DEFAULT_RETRY_AFTER: Duration = Duration::from_secs(5);

/// Why a message was not delivered.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SendError {
    /// HTTP 429: Telegram asks to wait this long before the next request.
    #[error("Telegram asked to wait {} s", .0.as_secs())]
    RetryAfter(Duration),
    /// HTTP 401: Telegram refused the bot token.
    #[error("Telegram refused the bot token")]
    TokenRejected,
    /// HTTP 403 or "chat not found": this chat cannot receive messages.
    #[error("Telegram refused the chat")]
    ChatUnavailable(DisabledReason),
    /// Another HTTP 4xx: Telegram refused this message.
    #[error("Telegram refused the message")]
    Rejected,
    /// A redirect, a server error, a timeout or a broken connection or reply; `status` is
    /// the HTTP status when there was one.
    #[error("Telegram could not be reached")]
    Transient {
        /// The HTTP status of the reply, if any.
        status: Option<u16>,
    },
    /// Every address of the Bot API host is one no outbound-policy setting admits.
    #[error("the Bot API address is refused by the outbound policy")]
    AddressRefused,
    /// The configured CA file could not be read.
    #[error("the Bot API CA file cannot be read")]
    CaFile,
    /// The configured CA file holds no valid certificate.
    #[error("the Bot API CA file is not a valid certificate")]
    Certificate,
    /// The HTTP client could not be built.
    #[error("the Bot API client cannot be built")]
    Client,
    /// No bot token is configured or notifications are off.
    #[error("Telegram notifications are not configured")]
    NotConfigured,
    /// The outbox has stopped.
    #[error("the notification outbox has stopped")]
    Stopped,
}

impl SendError {
    /// Maps a transport error, after dropping its URL.
    pub(super) fn from_transport(error: reqwest::Error) -> Self {
        let stripped = error.without_url();
        let mut source: Option<&(dyn StdError + 'static)> = Some(&stripped);
        while let Some(current) = source {
            if current.is::<AddressRefused>() {
                return Self::AddressRefused;
            }
            source = current.source();
        }
        Self::Transient {
            status: stripped.status().map(|status| status.as_u16()),
        }
    }

    /// Maps a reply that is not a success; `body` is the capped reply body, if read.
    pub(super) fn from_reply(status: StatusCode, body: Option<&[u8]>) -> Self {
        let reply: Option<Reply> = body.and_then(|bytes| serde_json::from_slice(bytes).ok());
        match status {
            StatusCode::TOO_MANY_REQUESTS => Self::RetryAfter(
                reply
                    .and_then(|parsed| parsed.parameters)
                    .and_then(|parameters| parameters.retry_after)
                    .map_or(DEFAULT_RETRY_AFTER, Duration::from_secs),
            ),
            StatusCode::UNAUTHORIZED => Self::TokenRejected,
            StatusCode::FORBIDDEN => Self::ChatUnavailable(DisabledReason::Forbidden),
            StatusCode::BAD_REQUEST
                if reply
                    .and_then(|parsed| parsed.description)
                    .is_some_and(|text| text.to_ascii_lowercase().contains("chat not found")) =>
            {
                Self::ChatUnavailable(DisabledReason::ChatNotFound)
            }
            other if other.is_client_error() => Self::Rejected,
            other => Self::Transient {
                status: Some(other.as_u16()),
            },
        }
    }
}

/// The parts of a Bot API error reply kcc reads.
#[derive(Deserialize)]
struct Reply {
    /// Human-readable reason; only searched for "chat not found".
    description: Option<String>,
    /// Extra fields of a 429 reply.
    parameters: Option<Parameters>,
}

/// `parameters` of a Bot API error reply.
#[derive(Deserialize)]
struct Parameters {
    /// Seconds to wait before the next request.
    retry_after: Option<u64>,
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test assertions are not rendered API documentation"
)]
mod tests {
    use core::time::Duration;

    use kcc_app::notify_store::DisabledReason;
    use reqwest::StatusCode;

    use super::SendError;

    /// Todo 8: each Bot API status maps to its delivery decision.
    #[test]
    fn replies_map_to_their_decision() {
        let cases: [(StatusCode, &[u8], SendError); 8] = [
            (
                StatusCode::TOO_MANY_REQUESTS,
                br#"{"ok":false,"parameters":{"retry_after":7}}"#,
                SendError::RetryAfter(Duration::from_secs(7)),
            ),
            (
                StatusCode::TOO_MANY_REQUESTS,
                b"{}",
                SendError::RetryAfter(Duration::from_secs(5)),
            ),
            (StatusCode::UNAUTHORIZED, b"", SendError::TokenRejected),
            (
                StatusCode::FORBIDDEN,
                b"",
                SendError::ChatUnavailable(DisabledReason::Forbidden),
            ),
            (
                StatusCode::BAD_REQUEST,
                br#"{"description":"Bad Request: chat not found"}"#,
                SendError::ChatUnavailable(DisabledReason::ChatNotFound),
            ),
            (
                StatusCode::BAD_REQUEST,
                br#"{"description":"Bad Request: message is too long"}"#,
                SendError::Rejected,
            ),
            (
                StatusCode::FOUND,
                b"",
                SendError::Transient { status: Some(302) },
            ),
            (
                StatusCode::BAD_GATEWAY,
                b"",
                SendError::Transient { status: Some(502) },
            ),
        ];
        for (status, body, expected) in cases {
            assert_eq!(
                SendError::from_reply(status, Some(body)),
                expected,
                "{status}"
            );
        }
    }
}
