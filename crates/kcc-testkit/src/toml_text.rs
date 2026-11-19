//! TOML text for test configurations written by hand.

use core::fmt::Write as _;
use std::path::Path;

/// `path` as a TOML basic string, quotes included, for a `kcc.toml` a test writes.
///
/// Backslashes, quotes and control characters are escaped, so a Windows path such as
/// `C:\Users\...` parses back to the same text instead of starting a `\U` escape.
#[inline]
#[must_use]
pub fn path(path: &Path) -> String {
    let text = path.to_string_lossy();
    let mut quoted = String::with_capacity(text.len().saturating_add(2));
    quoted.push('"');
    for character in text.chars() {
        match character {
            '"' => quoted.push_str("\\\""),
            '\\' => quoted.push_str("\\\\"),
            '\u{0}'..='\u{1f}' | '\u{7f}' => {
                let _written = write!(quoted, "\\u{:04X}", u32::from(character));
            }
            other => quoted.push(other),
        }
    }
    quoted.push('"');
    quoted
}
