//! `kcc mcp settings show`, `kcc mcp connections list|revoke|revoke-account` and
//! `kcc mcp clients list|delete` (todo 32): sources of the effective settings, the
//! listings without tokens or hashes, the confirmation and permission refusals with their
//! exit codes, and a revocation or client deletion by the CLI making a running
//! `kcc serve` refuse the very next MCP call of an open session.
//!
//! On Linux every `kcc` child runs with a 1 MiB main-thread stack (`ulimit -s 1024`), the
//! size Windows gives the main thread.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "integration tests drive the built process"
)]

#[path = "serve_oauth/browser.rs"]
mod browser;
#[expect(
    dead_code,
    reason = "the kcc sign-in suite's fixture; this suite needs part of it"
)]
#[path = "serve_oauth/fixture.rs"]
mod fixture;
#[expect(
    dead_code,
    reason = "the kcc sign-in suite's flow; this suite needs part of it"
)]
#[path = "serve_oauth/flow.rs"]
mod flow;
#[path = "support/master_key.rs"]
mod master_key;
#[expect(
    dead_code,
    reason = "the kcc sign-in suite's MCP client; this suite needs part of it"
)]
#[path = "serve_oauth/mcp.rs"]
mod mcp;
#[path = "support/serve_port.rs"]
mod serve_port;
#[path = "support/spawning.rs"]
mod spawning;
#[expect(
    dead_code,
    reason = "the kcc sign-in suite's token requests; this suite needs part of it"
)]
#[path = "serve_oauth/tokens.rs"]
mod tokens;

#[path = "cli_mcp/run.rs"]
mod run;

#[path = "cli_mcp/settings.rs"]
mod settings;

#[path = "cli_mcp/listing.rs"]
mod listing;

#[path = "cli_mcp/exits.rs"]
mod exits;

#[path = "cli_mcp/live.rs"]
mod live;
