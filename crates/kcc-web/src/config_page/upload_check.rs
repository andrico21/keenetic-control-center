//! What makes an uploaded file a startup configuration kcc stores as a backup.
//!
//! It must be text of at most 1 MiB, parse as a configuration with at least one command,
//! match its own checksum header when it has one, and not be a copy kcc redacted, since
//! storing that would make a backup without secrets.

use core::str;

use axum::http::StatusCode;
use fluent_bundle::FluentArgs;
use kcc_config::config_text::ParseError;
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_migrate::source::{SourceConfig, SourceError};
use secrecy::SecretString;

use super::{backup_rows::UPLOADED, store::REASON_ROOM, text::REDACTED_MARK};

/// Largest file stored as a backup: 1 MiB.
pub(crate) const FILE_LIMIT: usize = 0x0010_0000;

/// Longest file name kept in a reason: the page's room for a reason less `upload-`.
const NAME_ROOM: usize = REASON_ROOM.saturating_sub(UPLOADED.len()).saturating_sub(1);

/// Why a file is not stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// No file was chosen.
    Missing,
    /// Larger than [`FILE_LIMIT`].
    TooLarge,
    /// Not text.
    NotText,
    /// Text that does not parse as a configuration, at this line.
    Unparsable(usize),
    /// Its checksum header does not match its commands.
    Checksum,
    /// No configuration commands.
    Empty,
    /// A copy without secrets.
    Redacted,
}

impl Refusal {
    /// The status, the localized message and the audit outcome.
    pub(crate) fn describe(self, locale: Locale) -> (StatusCode, String, &'static str) {
        let (status, key, audit) = match self {
            Self::Missing => (
                StatusCode::UNPROCESSABLE_ENTITY,
                keys::WEB_CONFIG_UPLOAD_MISSING,
                "validation_failed",
            ),
            Self::TooLarge => (
                StatusCode::PAYLOAD_TOO_LARGE,
                keys::WEB_CONFIG_UPLOAD_TOO_LARGE,
                "too_large",
            ),
            Self::NotText => (
                StatusCode::UNPROCESSABLE_ENTITY,
                keys::WEB_CONFIG_UPLOAD_NOT_TEXT,
                "not_config",
            ),
            Self::Unparsable(_) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                keys::WEB_CONFIG_UPLOAD_PARSE,
                "not_config",
            ),
            Self::Checksum => (
                StatusCode::UNPROCESSABLE_ENTITY,
                keys::WEB_CONFIG_UPLOAD_CHECKSUM,
                "checksum",
            ),
            Self::Empty => (
                StatusCode::UNPROCESSABLE_ENTITY,
                keys::WEB_CONFIG_UPLOAD_EMPTY,
                "not_config",
            ),
            Self::Redacted => (
                StatusCode::UNPROCESSABLE_ENTITY,
                keys::WEB_CONFIG_UPLOAD_REDACTED,
                "redacted",
            ),
        };
        let mut args = FluentArgs::new();
        if let Self::Unparsable(line) = self {
            args.set("line", line);
        }
        (status, tr(locale, key, Some(&args)), audit)
    }
}

/// The reason and the text of an uploaded file named `name` that is a configuration.
///
/// # Errors
///
/// Returns why the file is not stored.
pub(crate) fn checked(name: Option<&str>, bytes: &[u8]) -> Result<(String, SecretString), Refusal> {
    if bytes.is_empty() {
        return Err(Refusal::Missing);
    }
    if bytes.len() > FILE_LIMIT {
        return Err(Refusal::TooLarge);
    }
    let text = str::from_utf8(bytes).map_err(|_error| Refusal::NotText)?;
    if text
        .chars()
        .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
    {
        return Err(Refusal::NotText);
    }
    let source = SourceConfig::from_bytes(bytes).map_err(|error| match error {
        SourceError::Parse(parse) => Refusal::Unparsable(line(&parse)),
        SourceError::ChecksumMismatch => Refusal::Checksum,
        SourceError::InvalidUtf8
        | SourceError::UseUploadedFile
        | SourceError::Rci(_)
        | SourceError::BackupNotResolved
        | _ => Refusal::NotText,
    })?;
    if source.ast.nodes.is_empty() {
        return Err(Refusal::Empty);
    }
    if source.header.extra.contains_key(REDACTED_MARK) {
        return Err(Refusal::Redacted);
    }
    Ok((reason(name), SecretString::from(text.to_owned())))
}

/// The line a parse error names.
const fn line(error: &ParseError) -> usize {
    match *error {
        ParseError::UnterminatedQuote { line }
        | ParseError::InvalidIndent {
            line,
            spaces: _,
            width: _,
        }
        | ParseError::IndentJump { line, level: _ } => line,
        _ => 0,
    }
}

/// The reason of an upload named `name`: `upload`, then the file name without its
/// extension in lowercase Latin letters, digits and hyphens.
fn reason(name: Option<&str>) -> String {
    let full = name.unwrap_or_default();
    let stem = full.rsplit_once('.').map_or(full, |(before, _)| before);
    let mut slug = String::new();
    for character in stem.chars() {
        match character {
            letter if letter.is_ascii_alphanumeric() => slug.push(letter.to_ascii_lowercase()),
            _ if slug.is_empty() || slug.ends_with('-') => {}
            _ => slug.push('-'),
        }
    }
    let kept: String = slug.chars().take(NAME_ROOM).collect();
    let tail = kept.trim_end_matches('-');
    if tail.is_empty() {
        UPLOADED.to_owned()
    } else {
        format!("{UPLOADED}-{tail}")
    }
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use super::{REASON_ROOM, Refusal, checked, reason};

    #[test]
    fn upload_reasons_keep_a_safe_file_stem() {
        assert_eq!(
            reason(Some("startup-config.txt")),
            "upload-startup-config",
            "stem"
        );
        assert_eq!(
            reason(Some("Ultra 2026 (copy).TXT")),
            "upload-ultra-2026-copy",
            "slug"
        );
        assert_eq!(reason(Some("--.txt")), "upload", "nothing left");
        assert_eq!(reason(None), "upload", "no name");
        assert!(
            reason(Some(&"x".repeat(90))).len() <= REASON_ROOM,
            "fits the store's reason with a copy number"
        );
    }

    #[test]
    fn only_configuration_text_is_accepted() {
        assert_eq!(
            checked(
                Some("a.png"),
                &[0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0xff]
            )
            .err(),
            Some(Refusal::NotText),
            "binary"
        );
        assert_eq!(
            checked(None, b"a\0b\n").err(),
            Some(Refusal::NotText),
            "NUL"
        );
        assert_eq!(
            checked(None, b"interface Bridge0\n  description x\n   up\n").err(),
            Some(Refusal::Unparsable(3)),
            "indentation"
        );
        assert_eq!(
            checked(None, b"! comment only\n").err(),
            Some(Refusal::Empty),
            "no command"
        );
        assert_eq!(
            checked(
                None,
                b"! $$$ kcc-redacted: true\nsystem\n description x\n!\n"
            )
            .err(),
            Some(Refusal::Redacted),
            "a redacted copy"
        );
        assert!(
            checked(None, b"system\n description x\n!\n").is_ok(),
            "a configuration"
        );
    }
}
