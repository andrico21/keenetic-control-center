//! Command and parameter catalog for the router RCI surface.

#![expect(
    clippy::pub_use,
    reason = "the crate root re-exports the established kcc-catalog public API"
)]

extern crate alloc;

mod catalog_types;
mod cli;
mod cli_grammar;
#[cfg(test)]
mod cli_leaf_tests;
/// Generated embedded catalog artifacts.
pub mod generated;
mod request;
mod runtime;
mod search;
mod secret_value;
mod validate;

pub use catalog_types::{
    Argument, ArgumentKind, CatalogError, CatalogVersion, Command, CommandKind, ModelMatch, Risk,
};
pub use request::ValidatedRequest;
pub use runtime::Catalog;
pub use search::SearchResult;
pub use secret_value::{SecretValue, WireValue};
pub use validate::{HttpMethod, RawAuthorization, RequestOptions, ValidationIssue};

#[cfg(test)]
mod cli_tests;
#[cfg(test)]
mod secret_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod typing_tests;
#[cfg(test)]
mod untyped_arguments_tests;
