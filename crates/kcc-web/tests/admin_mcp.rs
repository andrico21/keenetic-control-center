//! The MCP settings administration page: who may open it, where each value comes from,
//! the password asked for safety-reducing changes, live apply and restarts through a
//! stand-in for the running listeners, and the CA uploads.

#[expect(
    dead_code,
    reason = "the shared Web UI test support; this suite needs part of it"
)]
#[path = "support/mod.rs"]
mod support;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    reason = "test support is not rendered API documentation; every error fails the test"
)]
#[path = "admin_mcp/fixture.rs"]
mod fixture;

#[cfg(test)]
#[path = "admin_mcp/stub.rs"]
mod stub;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    reason = "test support is not rendered API documentation; every error fails the test"
)]
#[path = "admin_mcp/client.rs"]
mod client;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "admin_mcp/access.rs"]
mod access;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "admin_mcp/sources.rs"]
mod sources;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "admin_mcp/password.rs"]
mod password;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "admin_mcp/apply.rs"]
mod apply;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "admin_mcp/status.rs"]
mod status;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "admin_mcp/uploads.rs"]
mod uploads;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "admin_mcp/mtls.rs"]
mod mtls;
