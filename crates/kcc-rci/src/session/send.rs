//! The one place kcc-rci puts a request on the wire, and the label its log lines carry.

use core::time::Duration;
use std::time::Instant;

use reqwest::{Method, RequestBuilder, Response};

use super::{journal, map_reqwest_error};
use crate::RciError;

/// Longest path segment shown as written; longer or other segments are masked.
const MAX_SEGMENT_CHARS: usize = 64;

/// What one request's log lines say about it: never a query, a body or a value-like segment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RequestLabel<'id> {
    /// The router profile id of the client; empty when unset.
    pub router: &'id str,
    /// The HTTP method.
    pub method: Method,
    /// The request path without its query, value-like segments replaced by `*`.
    pub path: String,
    /// Whether a query was removed.
    pub query: bool,
}

impl<'id> RequestLabel<'id> {
    /// Labels a request of `router` to `target`, a path with an optional query.
    pub(crate) fn new(router: &'id str, method: &Method, target: &str) -> Self {
        let (path, query) = target
            .split_once('?')
            .map_or((target, false), |(path, _query)| (path, true));
        Self {
            router,
            method: method.clone(),
            path: masked(path),
            query,
        }
    }
}

/// `path` (without a query) with every value-like segment replaced by `*`.
pub(crate) fn masked(path: &str) -> String {
    path.split('/').map(segment).collect::<Vec<_>>().join("/")
}

/// `segment` when it is a name (`[A-Za-z][A-Za-z0-9_-]{0,63}`), a number or empty, else `*`.
fn segment(segment: &str) -> &str {
    let mut bytes = segment.bytes();
    let shown = match bytes.next() {
        None => true,
        Some(first) if first.is_ascii_alphabetic() => {
            segment.len() <= MAX_SEGMENT_CHARS
                && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        }
        Some(first) if first.is_ascii_digit() => bytes.all(|byte| byte.is_ascii_digit()),
        Some(_) => false,
    };
    if shown { segment } else { "*" }
}

/// Whole milliseconds of `elapsed`, saturating.
pub(crate) fn millis(elapsed: Duration) -> u64 {
    u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
}

/// Sends `builder` and logs the answer's status, announced length and duration at DEBUG,
/// or the cause of a request that got no answer.
///
/// # Errors
/// Returns [`RciError::Timeout`] or [`RciError::Transport`] when no answer arrived.
// NOT cancel-safe: a request dropped after transmission may still be processed by the router.
pub(crate) async fn send(
    builder: RequestBuilder,
    label: &RequestLabel<'_>,
) -> Result<Response, RciError> {
    let started = Instant::now();
    let result = builder
        .send()
        .await
        .map_err(|error| map_reqwest_error(&error));
    let ms = millis(started.elapsed());
    match &result {
        Ok(response) => tracing::debug!(
            router = %label.router,
            method = %label.method,
            path = %label.path,
            query = label.query.then_some(true),
            status = response.status().as_u16(),
            content_length = response.content_length(),
            ms,
            "router answered"
        ),
        Err(error) => tracing::debug!(
            router = %label.router,
            method = %label.method,
            path = %label.path,
            query = label.query.then_some(true),
            cause = %journal::Cause::of(error),
            ms,
            "router did not answer"
        ),
    }
    result
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test assertions are not rendered API documentation"
)]
mod tests {
    use reqwest::Method;

    use super::RequestLabel;

    /// Names and numbers stay, a query is noted, and every other segment is masked.
    #[test]
    fn value_like_segments_and_queries_never_reach_the_label() {
        let cases = [
            ("/rci/show/version", "/rci/show/version", false),
            ("/rci/", "/rci/", false),
            ("/rci/show/clock/date?name=x", "/rci/show/clock/date", true),
            ("/ci/startup-config.txt", "/ci/*", false),
            ("/rci/show/02:00:00:00:00:01/7", "/rci/show/*/7", false),
            ("/rci/a_b-C9/1x/x%20y/-z", "/rci/a_b-C9/*/*/*", false),
        ];
        for (target, path, query) in cases {
            let label = RequestLabel::new("r", &Method::GET, target);
            assert_eq!(
                (label.path.as_str(), label.query),
                (path, query),
                "{target}"
            );
        }
        let long = format!("/{}", "a".repeat(65));
        assert_eq!(RequestLabel::new("r", &Method::GET, &long).path, "/*");
        let longest = format!("/{}", "a".repeat(64));
        assert_eq!(RequestLabel::new("r", &Method::GET, &longest).path, longest);
    }
}
