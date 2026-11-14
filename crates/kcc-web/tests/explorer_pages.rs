//! Command explorer, RCI console and CLI console tests against the fake router: per-role
//! controls, catalog facts and the generated form, previews, reads, changes through the
//! change workflow, validation failures that send nothing, router refusals, confirmations,
//! the fail-safe guard, background jobs and the R-MCP2 incident payload.

#[expect(
    dead_code,
    reason = "the shared Web UI test support; this suite needs part of it"
)]
#[path = "support/mod.rs"]
mod support;

#[cfg(test)]
#[path = "explorer_pages/raw_management.rs"]
mod raw_management;

/// The R-MCP2 incident payload: a positional array where RCI needs an object.
pub(crate) const INCIDENT: &str = r#"{"ip":{"route":["10.0.5.0","255.255.255.255","Wireguard2"]}}"#;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "explorer_pages/browse.rs"]
mod browse;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "explorer_pages/execute.rs"]
mod execute;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "explorer_pages/consoles.rs"]
mod consoles;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "explorer_pages/guards.rs"]
mod guards;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "explorer_pages/persists.rs"]
mod persists;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "explorer_pages/refusal.rs"]
mod refusal;

#[cfg(test)]
#[path = "explorer_pages/bracket.rs"]
mod bracket;
#[cfg(test)]
#[path = "explorer_pages/destructive_management.rs"]
mod destructive_management;
#[cfg(test)]
#[path = "explorer_pages/nested_risk.rs"]
mod nested_risk;
