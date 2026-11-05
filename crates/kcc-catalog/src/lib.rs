//! Command and parameter catalog for the router RCI surface.

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
mod tests;
