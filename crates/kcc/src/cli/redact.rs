//! Configuration text without its secrets, as the Web UI's redacted download.

use kcc_config::{
    config_text::{flatten, parse},
    mask,
};

use super::exit::{Exit, Failure, Outcome};

/// `text` with every registered secret and every `ns3` blob replaced, marked as redacted
/// and without the router checksum that no longer matches it.
///
/// # Errors
///
/// Returns a validation failure when `text` is not a configuration.
pub(crate) fn redacted_copy(text: &str) -> Outcome<String> {
    mask::redacted_copy(text).map_err(|error| Failure::text(Exit::Validation, &error))
}

/// The flattened commands of `text` with secrets replaced.
///
/// # Errors
///
/// Returns a validation failure when `text` is not a configuration.
pub(crate) fn redacted_lines(text: &str) -> Outcome<Vec<String>> {
    let ast = parse(text).map_err(|error| Failure::text(Exit::Validation, &error))?;
    Ok(flatten(&mask::redacted_config(&ast))
        .iter()
        .map(ToString::to_string)
        .collect())
}
