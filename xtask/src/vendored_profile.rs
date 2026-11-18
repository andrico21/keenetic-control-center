//! The lint profile vendored in `docs/rust-guidelines/RUST_GUIDELINES.md`.
//!
//! The guidelines file is checksummed, so the TOML block that holds
//! `[workspace.lints.rust]` is the reference the root manifest is compared with.

use std::{fs, path::Path};

use toml::Table;

use crate::{failure::GateError, manifest};

/// Location of the vendored guidelines, relative to the repository root.
const GUIDELINES: [&str; 3] = ["docs", "rust-guidelines", "RUST_GUIDELINES.md"];

/// Opening fence of a TOML code block.
const FENCE_OPEN: &str = "```toml";

/// Closing fence of a code block.
const FENCE_CLOSE: &str = "```";

/// Marker line that identifies the block holding the lint tables.
const MARKER: &str = "[workspace.lints.rust]";

/// Reads the `workspace.lints` table of the vendored profile block.
///
/// # Errors
///
/// Returns [`GateError::Read`] when the guidelines cannot be read,
/// [`GateError::MissingTable`] when no TOML block holds `[workspace.lints.rust]`
/// or the block has no `workspace.lints` table, and [`GateError::Toml`] when the
/// block is not valid TOML.
pub(crate) fn read(root: &Path) -> Result<Table, GateError> {
    let path = GUIDELINES
        .iter()
        .fold(root.to_path_buf(), |path, part| path.join(part));
    let text = fs::read_to_string(&path).map_err(|source| GateError::Read {
        path: path.clone(),
        source,
    })?;
    let block = profile_block(&text).ok_or_else(|| GateError::MissingTable {
        path: path.clone(),
        key: MARKER.trim_matches(['[', ']']).to_owned(),
    })?;
    let doc = block.parse::<Table>().map_err(|source| GateError::Toml {
        path: path.clone(),
        source,
    })?;
    manifest::table_at(&doc, &manifest::WORKSPACE_LINTS, &path).cloned()
}

/// Returns the text of the first fenced TOML block that has a [`MARKER`] line.
fn profile_block(text: &str) -> Option<String> {
    let mut current: Option<Vec<&str>> = None;
    for line in text.lines() {
        match current.as_mut() {
            None => {
                if line.trim_end() == FENCE_OPEN {
                    current = Some(Vec::new());
                }
            }
            Some(body) => {
                if line.trim_end() == FENCE_CLOSE {
                    if body.iter().any(|row| row.trim_end() == MARKER) {
                        return Some(body.join("\n"));
                    }
                    current = None;
                } else {
                    body.push(line);
                }
            }
        }
    }
    None
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::error::Error;

    use super::profile_block;

    /// The block holding the lint tables is picked over an earlier TOML block.
    #[test]
    fn picks_the_block_with_the_lint_tables() -> Result<(), Box<dyn Error>> {
        let text = "```toml\n[profile.release]\nlto = true\n```\n\ntext\n\n\
            ```toml\n[workspace.lints.rust]\nunused = \"deny\"\n```\n";
        let block = profile_block(text).ok_or("no block")?;
        assert_eq!(block, "[workspace.lints.rust]\nunused = \"deny\"");
        Ok(())
    }

    /// A document without the marker yields no block.
    #[test]
    fn no_marker_yields_no_block() {
        assert!(profile_block("```toml\n[profile.release]\n```\n").is_none());
    }
}
