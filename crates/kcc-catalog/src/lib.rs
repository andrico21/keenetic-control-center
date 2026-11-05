//! Command and parameter catalog for the router RCI surface.

#![expect(
    clippy::pub_use,
    reason = "the crate root re-exports the established kcc-catalog public API"
)]

extern crate alloc;

mod cli;
/// Generated embedded catalog artifacts.
pub mod generated;
mod runtime;
mod search;
mod validate;

pub use runtime::{
    Argument, ArgumentKind, Catalog, CatalogError, CatalogVersion, Command, CommandKind,
    ModelMatch, Risk,
};
pub use search::SearchResult;
pub use validate::{
    HttpMethod, RawAuthorization, RequestOptions, ValidatedRequest, ValidationIssue,
};

#[cfg(test)]
mod cli_tests;
#[cfg(test)]
mod tests;
