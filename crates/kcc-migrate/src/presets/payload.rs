//! The sealed text of a preset: written from the preset's borrowed lines into one
//! exactly sized secret, and read back into zeroizing storage.

use std::io;

use kcc_config::config_text::CliLine;
use secrecy::SecretString;
use serde::{Deserialize as _, Deserializer, Serialize, Serializer, ser::Error as _};
use zeroize::{Zeroize as _, Zeroizing};

/// Command lines serialized as their text, one string each, without an owned copy.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct LineText<'lines>(&'lines [CliLine]);

impl<'lines> LineText<'lines> {
    /// Borrows `lines` for serialization.
    #[inline]
    #[must_use]
    pub const fn new(lines: &'lines [CliLine]) -> Self {
        Self(lines)
    }
}

impl Serialize for LineText<'_> {
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_seq(self.0.iter().map(Shown))
    }
}

/// One command line serialized through its `Display` text.
struct Shown<'line>(&'line CliLine);

impl Serialize for Shown<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self.0)
    }
}

/// Serializes `value` as JSON into one exactly sized secret.
///
/// The length is measured first, so the text is written once into a buffer of its final
/// size and no growth leaves a copy in freed memory.
///
/// # Errors
///
/// Returns the serialization failure of `value`.
#[inline]
pub fn secret_json<T>(value: &T) -> Result<SecretString, serde_json::Error>
where
    T: Serialize + ?Sized,
{
    let mut length = Length(0);
    serde_json::to_writer(&mut length, value)?;
    let mut bytes = Vec::with_capacity(length.0);
    serde_json::to_writer(&mut bytes, value)?;
    String::from_utf8(bytes)
        .map(SecretString::from)
        .map_err(|error| {
            error.into_bytes().zeroize();
            serde_json::Error::custom("serialized JSON is not UTF-8")
        })
}

/// Deserializes command text into storage wiped on drop.
///
/// # Errors
///
/// Returns the deserializer's failure.
#[inline]
pub fn zeroizing_lines<'de, D>(deserializer: D) -> Result<Zeroizing<Vec<String>>, D::Error>
where
    D: Deserializer<'de>,
{
    Vec::<String>::deserialize(deserializer).map(Zeroizing::new)
}

/// Counts written bytes and keeps none.
struct Length(usize);

impl io::Write for Length {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0 = self.0.saturating_add(buf.len());
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use core::error::Error;
    use std::process;

    use kcc_config::config_text::{flatten, parse};
    use secrecy::ExposeSecret as _;
    use serde::{Deserialize, Serialize};
    use serde_json::json;
    use zeroize::Zeroizing;

    use super::{LineText, secret_json, zeroizing_lines};

    /// What a sealed payload holds: the command text.
    #[derive(Serialize)]
    struct Sealed<'lines> {
        /// Borrowed command lines.
        lines: LineText<'lines>,
    }

    /// What an opened payload holds.
    #[derive(Deserialize)]
    struct Opened {
        /// Owned command text.
        #[serde(deserialize_with = "zeroizing_lines")]
        lines: Zeroizing<Vec<String>>,
    }

    /// W5-13: preset lines are serialized from the borrowed lines straight into one
    /// secret, in the same JSON as an owned list of strings (so sealed presets still
    /// open), and read back into zeroizing storage.
    #[test]
    fn sealed_lines_keep_the_stored_format() -> Result<(), Box<dyn Error>> {
        let secret = format!("x{}y", process::id());
        let ast = parse(&format!(
            "system\n    hostname \"edge \\\"one\\\"\"\nuser admin\n    password md5 {secret}\n"
        ))?;
        let lines = flatten(&ast);
        let owned = lines.iter().map(ToString::to_string).collect::<Vec<_>>();
        let text = secret_json(&Sealed {
            lines: LineText::new(&lines),
        })?;
        assert_eq!(
            text.expose_secret(),
            serde_json::to_string(&json!({ "lines": owned }))?,
            "same bytes as the owned payload"
        );
        let opened: Opened = serde_json::from_str(text.expose_secret())?;
        assert_eq!(*opened.lines, owned, "lines read back");
        Ok(())
    }
}
