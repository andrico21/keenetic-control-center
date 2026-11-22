//! The PEM shape of certificate files: one or more `CERTIFICATE` blocks of base64 and
//! nothing else. Whether they are CA certificates is checked where they are used.

use core::str;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use sha2::{Digest as _, Sha256};

/// The opening line of a certificate block.
const BEGIN: &str = "-----BEGIN CERTIFICATE-----";

/// The closing line of a certificate block.
const END: &str = "-----END CERTIFICATE-----";

/// The DER bytes of every certificate in `bytes`, or `None` when the file is not text,
/// holds no certificate, or holds anything besides certificate blocks and blank lines.
pub(crate) fn certificates(bytes: &[u8]) -> Option<Vec<Vec<u8>>> {
    let text = str::from_utf8(bytes).ok()?;
    let mut found = Vec::new();
    let mut body: Option<String> = None;
    for line in text.lines().map(str::trim) {
        match (&mut body, line) {
            (None, "") => {}
            (None, BEGIN) => body = Some(String::new()),
            (Some(collected), END) => {
                found.push(STANDARD.decode(collected.as_bytes()).ok()?);
                body = None;
            }
            (Some(collected), part) if !part.starts_with("-----") => collected.push_str(part),
            _ => return None,
        }
    }
    (body.is_none() && !found.is_empty()).then_some(found)
}

/// The SHA-256 fingerprint of the first certificate in `bytes`, as colon-separated
/// upper-case hex.
pub(crate) fn fingerprint(bytes: &[u8]) -> Option<String> {
    let first = certificates(bytes)?.into_iter().next()?;
    Some(
        Sha256::digest(&first)
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<Vec<_>>()
            .join(":"),
    )
}
