//! The MCP connections tab (todo 32): the live grants of kcc sign-in by account and
//! client, revoking one or every grant of an account, deleting a client with its grants,
//! pre-registering a client under the registration rules and the 50-client limit; who
//! may do it, the CSRF check, escaping of unverified names, and audit entries without
//! secrets.

#[expect(
    dead_code,
    reason = "the shared Web UI test support; this suite needs part of it"
)]
#[path = "support/mod.rs"]
mod support;

#[cfg(test)]
#[expect(
    dead_code,
    clippy::missing_errors_doc,
    reason = "the MCP settings page's fixture; this suite needs part of it"
)]
#[path = "admin_mcp/fixture.rs"]
mod fixture;

#[cfg(test)]
#[expect(dead_code, reason = "the MCP settings page's stand-in listeners")]
#[path = "admin_mcp/stub.rs"]
mod stub;

#[cfg(test)]
#[expect(
    dead_code,
    clippy::missing_errors_doc,
    reason = "the MCP settings page's browser; this suite needs part of it"
)]
#[path = "admin_mcp/client.rs"]
mod client;

#[cfg(test)]
#[expect(dead_code, reason = "each suite file uses part of the seed")]
#[path = "admin_mcp_connections/seed.rs"]
mod seed;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "admin_mcp_connections/listing.rs"]
mod listing;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "admin_mcp_connections/changes.rs"]
mod changes;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "admin_mcp_connections/register.rs"]
mod register;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "admin_mcp_connections/access.rs"]
mod access;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "admin_mcp_connections/confirmations.rs"]
mod confirmations;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "admin_mcp_connections/precision.rs"]
mod precision;
