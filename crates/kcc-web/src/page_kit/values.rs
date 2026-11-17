//! Typed values the change forms of several page families share, read from what was
//! typed at the boundary.

use core::net::Ipv4Addr;

use kcc_i18n::{bundle::MessageKey, keys};

/// An optional port from 1 to 65535; empty is none.
///
/// # Errors
///
/// Returns the port rule for text that is not such a port.
pub(crate) fn port(text: &str) -> Result<Option<u16>, MessageKey> {
    if text.is_empty() {
        return Ok(None);
    }
    match text.parse::<u16>() {
        Ok(found) if found > 0 => Ok(Some(found)),
        Ok(_) | Err(_) => Err(keys::WEB_ROUTING_ERROR_PORT),
    }
}

/// The dotted IPv4 netmask `text`, when its one bits are contiguous from the left
/// (`0.0.0.0` included).
pub(crate) fn netmask(text: &str) -> Option<Ipv4Addr> {
    text.parse::<Ipv4Addr>().ok().filter(|mask| {
        let bits = u32::from(*mask);
        bits.leading_ones().saturating_add(bits.trailing_zeros()) == 32
    })
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use super::netmask;

    #[test]
    fn masks_must_be_contiguous() {
        assert!(netmask("255.255.255.0").is_some(), "contiguous");
        assert!(netmask("0.0.0.0").is_some(), "default");
        assert!(netmask("255.0.255.0").is_none(), "holes");
        assert!(
            netmask("24").is_none(),
            "a prefix length is not a dotted mask"
        );
    }
}
