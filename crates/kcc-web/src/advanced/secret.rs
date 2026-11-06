//! Secret request and response members: recognized by name, because the catalog carries
//! no secret flag, and masked wherever a body or an answer is shown.

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

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use serde_json::json;

    use super::{MASK, is_secret, mask};

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
}
