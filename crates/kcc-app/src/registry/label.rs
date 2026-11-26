//! The display name of a router profile: free text people read, never a key. Logs,
//! metrics, audit records, URLs, state file names and `--router` keep the profile id.

/// Most characters a router display name holds.
pub const MAX_CHARS: usize = 64;

/// Why a router display name is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Fault {
    /// Longer than [`MAX_CHARS`] characters after trimming.
    #[error("label must be at most 64 characters")]
    TooLong,
    /// Holds a control character (`char::is_control`).
    #[error("label must not contain control characters")]
    Control,
}

/// Parses a router display name; a blank one means none.
///
/// Surrounding white space is trimmed; the rest must be at most [`MAX_CHARS`] characters
/// of any script without control characters. Names need not be unique. `kcc.toml`,
/// `routers.json`, the CLI and the Web UI all apply this rule.
///
/// # Errors
///
/// The [`Fault`] of a name the rule refuses.
#[inline]
pub fn parse(text: &str) -> Result<Option<String>, Fault> {
    let name = text.trim();
    if name.chars().any(char::is_control) {
        Err(Fault::Control)
    } else if name.chars().count() > MAX_CHARS {
        Err(Fault::TooLong)
    } else if name.is_empty() {
        Ok(None)
    } else {
        Ok(Some(name.to_owned()))
    }
}
