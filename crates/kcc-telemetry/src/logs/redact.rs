//! Redaction of MAC addresses before records leave the collector.

/// Replaces colon- or hyphen-delimited six-octet MAC addresses.
#[inline]
#[must_use]
pub fn macs(message: &str) -> String {
    let bytes = message.as_bytes();
    let mut output = String::with_capacity(message.len());
    let mut copied = 0_usize;
    let mut offset = 0_usize;
    while offset.saturating_add(17) <= bytes.len() {
        if is_mac(bytes, offset) {
            output.push_str(message.get(copied..offset).unwrap_or_default());
            output.push_str("[REDACTED-MAC]");
            offset = offset.saturating_add(17);
            copied = offset;
        } else {
            offset = offset.saturating_add(1);
        }
    }
    output.push_str(message.get(copied..).unwrap_or_default());
    output
}

/// Recognizes one bounded ASCII MAC address at `start`.
fn is_mac(bytes: &[u8], start: usize) -> bool {
    let Some(candidate) = bytes.get(start..start.saturating_add(17)) else {
        return false;
    };
    let Some(separator) = candidate.get(2).copied() else {
        return false;
    };
    if separator != b':' && separator != b'-' {
        return false;
    }
    let shape = candidate.iter().enumerate().all(|(index, byte)| {
        if matches!(index, 2 | 5 | 8 | 11 | 14) {
            *byte == separator
        } else {
            byte.is_ascii_hexdigit()
        }
    });
    let left = start.checked_sub(1).and_then(|index| bytes.get(index));
    let right = bytes.get(start.saturating_add(17));
    shape
        && left.is_none_or(|byte| !byte.is_ascii_hexdigit())
        && right.is_none_or(|byte| !byte.is_ascii_hexdigit())
}
