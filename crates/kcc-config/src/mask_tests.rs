//! The shared secret masker: secret member names, JSON answers and configuration text.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#![expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
use core::error::Error;

use serde_json::{Value, json};

use super::{
    REDACTED_MARK, is_secret_name, mask_json, mask_reply, redact_text, redact_text_with,
    redacted_copy,
};

/// SEC1-04: one rule names a secret member however it is spelt: hyphen or
/// underscore, any case, the short forms and the registry's argument names.
#[test]
fn secret_names_are_classified_in_every_form() {
    for secret in [
        "password",
        "Password",
        "PASSWD",
        "passphrase",
        "token",
        "authtoken",
        "api_key",
        "api-key",
        "private_key",
        "private-key",
        "Private-Key",
        "public-key",
        "ns3",
        "psk",
        "wpa-psk",
        "preshared-key",
        "preshare-key",
        "preshare_key",
        "obfs-key",
        "key",
        "KEY",
        "pin",
        "secret",
        "radiussecret",
        "uamsecret",
        "macpasswd",
        "community",
    ] {
        assert!(is_secret_name(secret), "{secret} is a secret");
    }
    for plain in [
        "key-id",
        "keygen",
        "passive1",
        "release-passive",
        "pinned",
        "mac",
        "host",
        "ssid",
        "name",
    ] {
        assert!(!is_secret_name(plain), "{plain} is not a secret");
    }
}

/// SEC1-04: a secret member is replaced whole by the caller's marker, whatever its
/// value: string, number, object, array, null or bool.
#[test]
fn mask_json_replaces_the_whole_member_of_any_type() {
    for marker in ["********", "<redacted>"] {
        for secret in [
            json!("text"),
            json!(42_i32),
            json!({"ns3": "blob", "plain": "x"}),
            json!(["a", {"b": 1_i32}]),
            Value::Null,
            json!(true),
        ] {
            let mut value = json!({
                "WifiMaster0/AccessPoint0": {"ssid": "home", "private-key": secret},
                "peers": [{"PSK": secret, "address": "203.0.113.7"}]
            });
            mask_json(&mut value, marker);
            assert_eq!(
                value,
                json!({
                    "WifiMaster0/AccessPoint0": {"ssid": "home", "private-key": marker},
                    "peers": [{"PSK": marker, "address": "203.0.113.7"}]
                }),
                "{secret} under {marker}"
            );
        }
    }
}

/// A-01, SEC2-07: configuration text keeps every line but the secrets.
///
/// Replaced: router-written `ns3` payloads, the IKE key's PSK (not its name), the IPsec
/// profile's secrets, the Wi-Fi PSK and the PPP password; other lines stay byte for byte.
#[test]
fn redact_text_replaces_every_secret_and_keeps_the_rest() {
    let [b1, b2, b3] = [1_u8, 2, 3].map(|index| format!("{}{index}", "QUJD".repeat(6)));
    let [ppp, preshared] = ["ppp", "profile"].map(|kind| format!("plain-{kind}-credential"));
    let head = "! $$$ Model: KN-1811\n!\n";
    let text = format!(
        "{head}interface WifiMaster0/AccessPoint0\n    ssid home\n    \
         authentication wpa-psk ns3 {b1}\n!\n\
         interface PPPoE0\n    authentication identity user1\n    \
         authentication password {ppp}\n!\n\
         crypto ike key office ns3 {b2} any\n\
         crypto ipsec profile office\n    preshared-key {preshared}\n    \
         xauth-password ns3 {b3}\n!\n\
         system\n    description \"two  words\"\r\n!\n"
    );
    assert_eq!(
        redact_text(&text),
        format!(
            "{head}interface WifiMaster0/AccessPoint0\n    ssid home\n    \
             authentication wpa-psk <redacted>\n!\n\
             interface PPPoE0\n    authentication identity user1\n    \
             authentication password <redacted>\n!\n\
             crypto ike key office <redacted> any\n\
             crypto ipsec profile office\n    preshared-key <redacted>\n    \
             xauth-password <redacted>\n!\n\
             system\n    description \"two  words\"\r\n!\n"
        )
    );
}

/// A line on its own, as a reply's line array carries it, is redacted without its
/// block; a line that cannot be read shows only the marker.
#[test]
fn redact_text_redacts_lone_and_unreadable_lines() {
    let blob = "QUJD".repeat(6);
    assert_eq!(
        redact_text(&format!("    authentication wpa-psk ns3 {blob}")),
        "    authentication wpa-psk <redacted>"
    );
    assert_eq!(
        redact_text(&format!("  system description \"{blob}")),
        "  <redacted>"
    );
}

/// The download copy keeps the settings, loses every secret and the stale checksum,
/// and is marked as redacted.
#[test]
fn the_redacted_copy_keeps_settings_and_loses_every_secret() -> Result<(), Box<dyn Error>> {
    let blob = "QUJD".repeat(6);
    let community = ["private", "community"].join("-");
    let copy = redacted_copy(&format!(
        "! $$$ Model: KN-1811\n! $$$ Md5 checksum: 0123456789abcdef0123456789abcdef\n\
         interface WifiMaster0/AccessPoint0\n authentication wpa-psk ns3 {blob}\n!\n\
         ip http proxy cloud upstream ns3 {blob}\n!\nsnmp community {community}\n!\n\
         system\n description visible\n!\n"
    ))?;
    assert!(!copy.contains("ns3 "), "no ns3 marker: {copy}");
    assert!(!copy.contains(&blob), "no blob: {copy}");
    assert!(!copy.contains(&community), "no community: {copy}");
    assert!(
        copy.contains("system\n description visible"),
        "settings kept"
    );
    assert!(
        copy.contains(&format!("! $$$ {REDACTED_MARK}: true")),
        "marked"
    );
    assert!(!copy.contains("Md5 checksum"), "no stale checksum: {copy}");
    Ok(())
}

/// The caller's marker replaces exactly the words `redact_text` would replace, in
/// readable and unreadable lines alike.
#[test]
fn redact_text_with_uses_the_callers_marker() {
    let blob = "QUJD".repeat(6);
    let text = format!(
        "interface PPPoE0\n    authentication password ns3 {blob}\n    description \"open\n"
    );
    assert_eq!(
        redact_text_with(&text, "********"),
        "interface PPPoE0\n    authentication password ********\n    ********\n"
    );
    assert_eq!(
        redact_text_with(&text, "<redacted>"),
        redact_text(&text),
        "the default marker is the plain form"
    );
}

/// A router answer loses its secret-named members and the secrets in its strings: the
/// configuration lines of an array, a lone text and a nested member.
#[test]
fn mask_reply_masks_members_and_configuration_strings() {
    let blob = "QUJD".repeat(6);
    let mut reply = json!({
        "message": ["interface PPPoE0", format!("    authentication password ns3 {blob}")],
        "text": format!("crypto ike key office ns3 {blob} any"),
        "PPPoE0": {"authentication": {"password": {"ns3": blob}}},
        "count": 2_u8,
    });
    mask_reply(&mut reply, "<redacted>");
    assert_eq!(
        reply,
        json!({
            "message": ["interface PPPoE0", "    authentication password <redacted>"],
            "text": "crypto ike key office <redacted> any",
            "PPPoE0": {"authentication": {"password": "<redacted>"}},
            "count": 2_u8,
        })
    );
}
