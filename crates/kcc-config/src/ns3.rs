//! NDM Secure v3 password encoding and decoding.

use core::str;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use md5::{Digest as _, Md5};
use secrecy::{ExposeSecret as _, SecretString};
use thiserror::Error;
use zeroize::Zeroizing;

/// NS3 encoding or decoding failure.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
#[expect(
    clippy::module_name_repetitions,
    reason = "Ns3Error is the public domain-specific error name required by the crate API"
)]
pub enum Ns3Error {
    /// The decoded payload does not use one of the NS3 block sizes.
    #[error("invalid NS3 payload length")]
    InvalidLength,
    /// The encoded payload is not valid Base64.
    #[error("invalid NS3 Base64 payload")]
    InvalidBase64,
    /// The decoded secret is not valid UTF-8.
    #[error("invalid UTF-8 in NS3 payload")]
    InvalidUtf8,
    /// The plaintext is empty or longer than 63 bytes.
    #[error("NS3 plaintext length must be between 1 and 63 bytes")]
    InvalidPlaintextLength,
}

/// Decodes an NS3 Base64 payload into zeroizing secret storage.
///
/// # Errors
///
/// Returns [`Ns3Error`] when the payload is malformed or has an invalid block size.
#[inline]
#[expect(
    clippy::arithmetic_side_effects,
    clippy::integer_division,
    clippy::integer_division_remainder_used,
    reason = "NS3 specifies marker positions using exact integer division and remainder on validated block lengths"
)]
pub fn decode(encoded: &str) -> Result<SecretString, Ns3Error> {
    let mut padded = Zeroizing::new(String::with_capacity(encoded.len().next_multiple_of(4)));
    padded.push_str(encoded);
    while !padded.len().is_multiple_of(4) {
        padded.push('=');
    }
    let mut bytes = Zeroizing::new(
        STANDARD
            .decode(padded.as_bytes())
            .map_err(|_error| Ns3Error::InvalidBase64)?,
    );
    let length = bytes.len();
    if !matches!(length, 0x12 | 0x24 | 0x48) {
        return Err(Ns3Error::InvalidLength);
    }

    let second_position = length / 7;
    let second_marker = bytes.remove(second_position);
    let first_position = usize::from(second_marker) % (length - 1);
    let first_marker = bytes.remove(first_position);
    second_step(&mut bytes);
    first_step(&mut bytes, first_marker, second_marker);

    let secret_length = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    bytes.truncate(secret_length);
    str::from_utf8(&bytes)
        .map(SecretString::from)
        .map_err(|_error| Ns3Error::InvalidUtf8)
}

/// Encodes a plaintext secret with the NS3 scrambling algorithm.
///
/// # Errors
///
/// Returns [`Ns3Error::InvalidPlaintextLength`] unless the secret is 1 through 63 bytes.
#[inline]
#[expect(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::integer_division,
    clippy::integer_division_remainder_used,
    reason = "NS3's bounded block construction and 16-byte digest define these indices and integer operations"
)]
pub fn encode(secret: &SecretString) -> Result<String, Ns3Error> {
    let plaintext = secret.expose_secret().as_bytes();
    let old_length = plaintext.len();
    if !(1..=63).contains(&old_length) {
        return Err(Ns3Error::InvalidPlaintextLength);
    }
    let length = match old_length + 3 {
        0..=0x12 => 0x12,
        0x13..=0x24 => 0x24,
        0x25..=0x48 => 0x48,
        _ => return Err(Ns3Error::InvalidPlaintextLength),
    };

    let digest = Md5::digest(plaintext);
    let mut bytes = Zeroizing::new(Vec::with_capacity(length));
    bytes.extend_from_slice(plaintext);
    bytes.push(0);
    for position in old_length.saturating_add(1)..length.saturating_sub(2) {
        let source_position = position - old_length - 1;
        let digest_position = 2 + position % 14;
        let source = bytes[source_position];
        bytes.push(source.wrapping_mul(2).wrapping_add(digest[digest_position]));
    }

    let first_marker = digest[0];
    let second_marker = digest[1];
    first_step(&mut bytes, first_marker, second_marker);
    second_step(&mut bytes);
    bytes.insert(usize::from(second_marker) % (length - 1), first_marker);
    bytes.insert(length / 7, second_marker);
    Ok(STANDARD.encode(bytes.as_slice()))
}

/// Applies the Fibonacci-stream XOR transformation used by NS3.
fn first_step(bytes: &mut [u8], mut first: u8, mut second: u8) {
    for byte in bytes {
        *byte ^= second;
        let next = first.wrapping_add(second);
        first = second;
        second = next;
    }
}

/// Applies the payload-wide XOR mask transformation used by NS3.
fn second_step(bytes: &mut [u8]) {
    let mut mask = bytes.iter().fold(0, |accumulator, byte| accumulator ^ byte);
    for shift in 1_u32..8_u32 {
        let intermediate = (mask >> shift) ^ ((!mask) << shift);
        mask = (intermediate << shift) ^ ((!intermediate) ^ mask);
    }
    for byte in bytes {
        *byte ^= mask;
    }
}

#[cfg(test)]
mod tests {
    //! Unit checks for published NS3 known-answer vectors.

    use proptest::prelude::{Strategy as _, prop, proptest};
    use secrecy::{ExposeSecret as _, SecretString};

    use super::{Ns3Error, decode, encode};

    /// Verifies all public R-NS3 known-answer vectors.
    ///
    /// # Panics
    ///
    /// Panics when a published vector fails to decode to its known plaintext.
    #[test]
    fn decodes_known_vectors() {
        let vectors = [
            ("QP/a3C96cTqJxMboZoZojIZB", "gdata"),
            ("57QZ+pHpr1U563wnqus9ZIKM", "z4c4StLAa6"),
            ("ClkGVb4VylHfkHQBQAg2jSUN", "1357924680"),
        ];
        for (encoded, plaintext) in vectors {
            let decoded = decode(encoded);
            assert!(decoded.is_ok(), "vector {encoded} must decode");
            assert_eq!(
                decoded.as_ref().map(secrecy::ExposeSecret::expose_secret),
                Ok(plaintext),
                "vector {encoded}"
            );
        }
    }

    /// Verifies the required malformed-length behavior.
    ///
    /// # Panics
    ///
    /// Panics when an invalid payload length is accepted or misclassified.
    #[test]
    fn rejects_invalid_length() {
        assert!(matches!(decode("abc"), Err(Ns3Error::InvalidLength)));
    }

    /// Verifies that encoding follows the public algorithm, not only decoding.
    ///
    /// # Panics
    ///
    /// Panics when encoding does not reproduce the published known-answer payload.
    #[test]
    fn encodes_published_vector() {
        let secret = SecretString::from("gdata".to_owned());
        assert_eq!(encode(&secret).as_deref(), Ok("QP/a3C96cTqJxMboZoZojIZB"));
    }

    proptest! {
        /// Printable ASCII passwords round-trip across every supported block size.
        #[test]
        fn printable_ascii_round_trips(
            plaintext in prop::collection::vec(0x20_u8..=0x7e, 1..=63)
                .prop_map(|bytes| String::from_utf8(bytes).unwrap_or_default())
        ) {
            let secret = SecretString::from(plaintext.clone());
            let encoded = encode(&secret)?;
            let decoded = decode(&encoded)?;
            proptest::prop_assert_eq!(decoded.expose_secret(), &plaintext);
        }
    }
}
