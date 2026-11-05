//! The `x-ndw2-interactive` challenge-response hash.
//!
//! `response = sha256(challenge || md5hex(login ":" realm ":" password))`, both digests
//! rendered as lowercase hex.

use md5::{Digest as _, Md5};
use sha2::Sha256;
use zeroize::Zeroizing;

/// Appends `bytes` to `out` as lowercase hex.
fn push_hex(out: &mut String, bytes: &[u8]) {
    for &byte in bytes {
        for nibble in [byte >> 4_u8, byte & 0x0f_u8] {
            out.push(char::from_digit(u32::from(nibble), 16).unwrap_or('0'));
        }
    }
}

/// `md5hex(login ":" realm ":" password)`, the per-user secret the router stores.
#[inline]
#[must_use]
pub fn ha1(login: &str, realm: &str, password: &str) -> Zeroizing<String> {
    let mut md5 = Md5::new();
    md5.update(login.as_bytes());
    md5.update(b":");
    md5.update(realm.as_bytes());
    md5.update(b":");
    md5.update(password.as_bytes());
    let mut hex = Zeroizing::new(String::with_capacity(32));
    push_hex(&mut hex, &md5.finalize());
    hex
}

/// `sha256hex(challenge || ha1)`, the value the client posts as `password`.
#[inline]
#[must_use]
pub fn response_from_ha1(challenge: &str, ha1: &str) -> String {
    let mut sha256 = Sha256::new();
    sha256.update(challenge.as_bytes());
    sha256.update(ha1.as_bytes());
    let mut hex = String::with_capacity(64);
    push_hex(&mut hex, &sha256.finalize());
    hex
}

/// The full ndw2 response for a login, realm, password and challenge.
#[inline]
#[must_use]
pub fn response(login: &str, realm: &str, password: &str, challenge: &str) -> String {
    response_from_ha1(challenge, &ha1(login, realm, password))
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use super::response;

    /// Known-answer vector from hexqnt/keenetic-rci `src/auth.rs` (MIT OR Apache-2.0).
    #[test]
    fn known_vector() {
        assert_eq!(
            response(
                "admin",
                "Keenetic Ultra",
                "secret",
                "0123456789abcdef0123456789abcdef"
            ),
            "9071bc0aeee8b97dfe926020c8aaeb35951c0f67998f1027eea5465643bc3632"
        );
    }
}
