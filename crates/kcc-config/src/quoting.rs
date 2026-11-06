//! Bounded CLI argument encoding for secret-bearing writes.

use secrecy::SecretString;
use thiserror::Error;

/// Maximum UTF-8 byte length of a plaintext CLI secret.
pub const MAX_SECRET_BYTES: usize = 256;

/// A CLI word that cannot be represented by the secret-writing contract.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum QuoteError {
    /// Input exceeds the shared plaintext byte limit.
    #[error("CLI argument exceeds 256 UTF-8 bytes")]
    TooLong,
    /// Input contains a Unicode control character.
    #[error("CLI argument contains a control character")]
    ControlCharacter,
}

/// Encodes one printable UTF-8 word in zeroizing secret storage.
///
/// Words are always double quoted; `"` and `\` are escaped. The result follows
/// [`crate::config_text::parse`], not shell syntax. Catalog-specific length bounds
/// must also be enforced by the caller before transmission.
///
/// # Errors
///
/// Returns [`QuoteError`] for control characters (including NUL, CR, LF and TAB)
/// or input longer than 256 UTF-8 bytes. Errors never retain input material.
#[inline]
pub fn quote_cli_word(word: &str) -> Result<SecretString, QuoteError> {
    if word.len() > MAX_SECRET_BYTES {
        return Err(QuoteError::TooLong);
    }
    if word.chars().any(char::is_control) {
        return Err(QuoteError::ControlCharacter);
    }
    let mut encoded = String::with_capacity(word.len().saturating_mul(2).saturating_add(2));
    encoded.push('"');
    for character in word.chars() {
        if matches!(character, '"' | '\\') {
            encoded.push('\\');
        }
        encoded.push(character);
    }
    encoded.push('"');
    Ok(SecretString::from(encoded))
}

#[cfg(test)]
#[expect(clippy::missing_panics_doc, reason = "tests fail through assertions")]
mod tests {
    //! Round trips exercise the real configuration tokenizer.

    use proptest::{
        prelude::proptest,
        test_runner::{Config, RngSeed},
    };
    use secrecy::ExposeSecret as _;

    use super::{QuoteError, quote_cli_word};
    use crate::config_text::{Token, parse};

    proptest! {
        #![proptest_config(Config { cases: 256, rng_seed: RngSeed::Fixed(31), ..Config::default() })]
        /// Quoted input stays one argument, including Unicode and CLI punctuation.
        #[test]
        fn quoted_word_round_trips(word in "[^\\p{Cc}]{1,256}") {
            if word.len() <= 256 {
                let quoted = quote_cli_word(&word)?;
                let ast = parse(&format!("description {}", quoted.expose_secret()))?;
                let tokens = ast.nodes.first().map(|node| node.tokens.as_slice());
                assert!(matches!(tokens, Some([Token::Word(command), Token::Word(value)])
                    if command == "description" && value == &word), "word must remain one unchanged argument");
            } else {
                assert_eq!(quote_cli_word(&word).err(), Some(QuoteError::TooLong));
            }
        }
    }

    /// Every control class is rejected and the byte limit is inclusive.
    #[test]
    fn rejects_controls_and_bounds_bytes() {
        for control in ['\0', '\n', '\r', '\t', '\u{7f}', '\u{85}'] {
            assert_eq!(
                quote_cli_word(&format!("prefix{control}suffix")).err(),
                Some(QuoteError::ControlCharacter)
            );
        }
        assert_eq!(
            quote_cli_word(&"x".repeat(257)).err(),
            Some(QuoteError::TooLong)
        );
        assert!(
            quote_cli_word(&"x".repeat(256)).is_ok(),
            "256 bytes must fit"
        );
    }
}
