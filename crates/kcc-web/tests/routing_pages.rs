//! The routing, port forwarding and firewall pages against the fake router.
//!
//! Each page is checked per role, with changes applied and read back from the router,
//! values refused before anything is sent, changes the router refuses shown with its words,
//! the route-wipe guard's banner after an injected router-wide clear, the router's pages of
//! 200 active connections, the IPv6 access-list note on a 4.3.9 router, and no secret on
//! any page.

#[expect(
    dead_code,
    reason = "the shared Web UI test support; this suite needs part of it"
)]
#[path = "support/mod.rs"]
mod support;

use axum::{http::StatusCode, response::Response};

use crate::support::{
    outcome::TestResult,
    page::{form, text},
    web::{Browser, Fixture},
};

/// `POST path` with `pairs` as `browser`, answered with `expected`: the body.
///
/// # Errors
///
/// Fails the test when the request fails or answers another status.
pub(crate) async fn post(
    fixture: &Fixture,
    browser: &Browser,
    (path, pairs): (&str, &[(&str, &str)]),
    expected: StatusCode,
) -> TestResult<String> {
    let response = fixture.post(path, browser, &form(pairs)).await?;
    answered(path, response, expected).await
}

/// `GET path` as `browser`, answered with `expected`: the body.
///
/// # Errors
///
/// Fails the test when the request fails or answers another status.
pub(crate) async fn get(
    fixture: &Fixture,
    browser: &Browser,
    path: &str,
    expected: StatusCode,
) -> TestResult<String> {
    let response = fixture.get(path, browser).await?;
    answered(path, response, expected).await
}

/// The body of `response` to `path` when it has the `expected` status.
///
/// # Errors
///
/// Fails the test with the status and the body otherwise.
async fn answered(path: &str, response: Response, expected: StatusCode) -> TestResult<String> {
    let status = response.status();
    let body = text(response).await?;
    if status == expected {
        Ok(body)
    } else {
        Err(format!("{path}: {status} instead of {expected}: {body}").into())
    }
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "routing_pages/routes.rs"]
mod routes;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "routing_pages/guard.rs"]
mod guard;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "routing_pages/policies.rs"]
mod policies;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "routing_pages/nat.rs"]
mod nat;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "routing_pages/firewall.rs"]
mod firewall;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "routing_pages/firewall_bind.rs"]
mod firewall_bind;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "routing_pages/refusals.rs"]
mod refusals;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "routing_pages/access.rs"]
mod access;
