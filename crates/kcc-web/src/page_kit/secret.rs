//! Secrets on pages: write-only fields, and secret members masked in raw answers.
//!
//! A secret a user types travels from its form field straight into a `SecretString`; an
//! empty field keeps the stored secret, and no page renders a stored value
//! (`kit::secret_field` has no value parameter). The one way to see a stored secret is
//! the audited Reveal action ([`super::reveal`]). Raw requests and answers carry no
//! secret flag, so their secret members are recognized by name and masked.

use secrecy::SecretString;
use serde_json::Value;

/// What a masked secret shows instead of its value.
pub(crate) const MASK: &str = "********";

/// Whether an argument or response member named `name` holds a secret.
pub(crate) fn is_secret(name: &str) -> bool {
    const EXACT: [&str; 9] = [
        "key",
        "psk",
        "pin",
        "secret",
        "password",
        "passwd",
        "token",
        "authtoken",
        "community",
    ];
    const SUFFIXES: [&str; 5] = ["-key", "secret", "password", "passwd", "psk"];
    let lower = name.to_ascii_lowercase();
    EXACT.contains(&lower.as_str()) || SUFFIXES.iter().any(|suffix| lower.ends_with(suffix))
}

/// Replaces every secret member of `value` with [`MASK`].
pub(crate) fn mask(value: &mut Value) {
    match value {
        Value::Object(object) => {
            for (name, member) in object.iter_mut() {
                if is_secret(name) && !member.is_object() && !member.is_array() {
                    *member = Value::String(MASK.to_owned());
                } else {
                    mask(member);
                }
            }
        }
        Value::Array(items) => items.iter_mut().for_each(mask),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

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
    use serde_json::json;

    use super::{MASK, is_secret, mask, write_only};

    #[test]
    fn secrets_are_classified_by_name_and_masked() {
        for secret in [
            "password",
            "psk",
            "private-key",
            "preshared-key",
            "radiussecret",
            "macpasswd",
            "key",
        ] {
            assert!(is_secret(secret), "{secret}");
        }
        for plain in [
            "key-id",
            "keygen",
            "passive1",
            "release-passive",
            "mac",
            "host",
        ] {
            assert!(!is_secret(plain), "{plain}");
        }
        let mut value = json!({"interface":{"psk":"hunter22","ssid":"home","peers":[{"key":"k"}]}});
        mask(&mut value);
        assert_eq!(
            value,
            json!({"interface":{"psk":MASK,"ssid":"home","peers":[{"key":MASK}]}}),
            "masked"
        );
    }

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
