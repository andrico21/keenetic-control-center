//! Unit tests of the MCP core: registration, gates, shaping, and argument fuzzing.
#![expect(
    clippy::absolute_paths,
    clippy::assertions_on_result_states,
    clippy::expect_used,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::std_instead_of_alloc,
    reason = "test fixtures use direct filesystem setup and assertions rather than public API documentation"
)]
#![expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]

pub(crate) mod fixture;
mod gates;
mod metadata;
mod persists;
mod privacy;
mod random;
mod shaping;
mod strategies;
