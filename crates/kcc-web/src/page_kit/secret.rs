//! Secrets on pages: write-only fields, and secret members masked in raw answers.
//!
//! A secret a user types travels from its form field straight into a `SecretString`; an
//! empty field keeps the stored secret, and no page renders a stored value
//! (`kit::secret_field` has no value parameter). Raw requests and answers carry no
//! secret flag, so their secret members are recognized by name and masked with [`MASK`]
//! by `kcc_config::mask`.

use secrecy::SecretString;

/// What a masked secret shows instead of its value.
pub(crate) const MASK: &str = "********";

/// The value of a write-only field: `None` when it was left empty, which keeps the stored
/// secret; else the typed secret, moved into a `SecretString` before any other use.
pub(crate) fn write_only(typed: String) -> Option<SecretString> {
    (!typed.is_empty()).then(|| SecretString::from(typed))
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use secrecy::ExposeSecret as _;

    use super::write_only;

    #[test]
    fn an_empty_write_only_field_keeps_the_stored_secret() {
        assert!(write_only(String::new()).is_none(), "kept");
        assert_eq!(
            write_only(" new pass ".to_owned())
                .as_ref()
                .map(|secret| secret.expose_secret().to_owned()),
            Some(" new pass ".to_owned()),
            "taken as typed, spaces included"
        );
    }
}
