//! A stored configuration as the page may show it: secrets replaced, as flattened lines.
//!
//! kcc-config's registry replaces the secrets it knows by their command; every `ns3` blob
//! is replaced as well, whatever command carries it. Two configurations compare by a
//! digest of each command's complete text, so a changed secret still marks its line as
//! changed while the page shows that line only with the secret replaced.

use kcc_config::{
    config_text::{CliLine, ParseError, flatten, parse},
    mask::redacted_config,
};
use secrecy::{ExposeSecret as _, SecretString};
use sha2::{Digest as _, Sha256};

/// The flattened commands of one configuration.
pub(crate) struct Lines {
    /// SHA-256 of each command's complete text, secrets included.
    digests: Vec<[u8; 32]>,
    /// Each command with its secrets replaced, in the same order.
    shown: Vec<String>,
}

impl Lines {
    /// The commands of `text`.
    ///
    /// # Errors
    ///
    /// Returns why `text` is not a configuration.
    pub(crate) fn read(text: &str) -> Result<Self, ParseError> {
        let ast = parse(text)?;
        let digests = flatten(&ast).iter().map(digest).collect();
        let shown = flatten(&redacted_config(&ast))
            .iter()
            .map(ToString::to_string)
            .collect();
        Ok(Self { digests, shown })
    }

    /// The digest of each command, in order.
    pub(crate) fn digests(&self) -> &[[u8; 32]] {
        &self.digests
    }

    /// Command `index` with its secrets replaced.
    pub(crate) fn shown(&self, index: usize) -> &str {
        self.shown.get(index).map_or("", String::as_str)
    }
}

/// The digest of one command's complete text, which lives only in a secret buffer.
fn digest(line: &CliLine) -> [u8; 32] {
    let text = SecretString::from(line.to_string());
    Sha256::digest(text.expose_secret().as_bytes()).into()
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

    use super::Lines;

    /// A configuration with a registered secret, an `ns3` blob nobody registered and a
    /// plain setting; `blob` is made at run time so no blob-shaped literal is committed.
    fn config(blob: &str, community: &str) -> String {
        format!(
            "! $$$ Model: KN-1811\n! $$$ Md5 checksum: 0123456789abcdef0123456789abcdef\n\
             interface WifiMaster0/AccessPoint0\n authentication wpa-psk ns3 {blob}\n!\n\
             ip http proxy cloud upstream ns3 {blob}\n!\nsnmp community {community}\n!\n\
             system\n description visible\n!\n"
        )
    }

    #[test]
    fn a_changed_secret_changes_its_line_but_not_what_is_shown() -> Result<(), Box<dyn Error>> {
        let old = Lines::read(&config(&"QUJD".repeat(6), "one"))?;
        let new = Lines::read(&config(&"REVG".repeat(6), "one"))?;
        assert_eq!(old.digests().len(), 4, "four commands");
        assert_ne!(
            old.digests().first(),
            new.digests().first(),
            "the PSK changed"
        );
        assert_eq!(
            old.digests().last(),
            new.digests().last(),
            "the rest did not"
        );
        assert_eq!(
            old.shown(0),
            "interface WifiMaster0/AccessPoint0 authentication wpa-psk <redacted>",
            "shown without the secret"
        );
        assert_eq!(old.shown(0), new.shown(0), "the same once redacted");
        assert_eq!(old.shown(9), "", "past the end");
        Ok(())
    }
}
