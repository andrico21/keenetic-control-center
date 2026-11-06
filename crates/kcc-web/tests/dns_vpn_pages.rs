//! The DNS and VPN pages against the fake router: what each role sees and may do, a change
//! applied and read back with the unsaved badge, a value refused before anything is sent,
//! a router refusal shown in the router's words, and the WireGuard `.conf` upload with
//! its 64 KiB cap, its field-level errors and its secrets kept off every page and log.

#[path = "explorer_pages/support.rs"]
mod support;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use kcc_i18n::{
    bundle::{MessageKey, tr},
    locale::Locale,
};
use url::form_urlencoded::byte_serialize;

/// `text` as askama escapes it.
pub(crate) fn html(text: &str) -> String {
    text.replace('&', "&#38;")
        .replace('<', "&#60;")
        .replace('>', "&#62;")
        .replace('"', "&#34;")
        .replace('\'', "&#39;")
}

/// A message in `locale`, escaped for HTML.
pub(crate) fn said(locale: Locale, key: MessageKey) -> String {
    html(&tr(locale, key, None))
}

/// `pairs` form-encoded.
pub(crate) fn form(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(name, value)| {
            format!(
                "{}={}",
                byte_serialize(name.as_bytes()).collect::<String>(),
                byte_serialize(value.as_bytes()).collect::<String>()
            )
        })
        .collect::<Vec<_>>()
        .join("&")
}

/// A WireGuard key made at run time from `byte`, so no key-shaped literal is committed.
pub(crate) fn key(byte: u8) -> String {
    STANDARD.encode([byte; 32])
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "dns_vpn_pages/dns.rs"]
mod dns;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "dns_vpn_pages/vpn.rs"]
mod vpn;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "dns_vpn_pages/upload.rs"]
mod upload;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "dns_vpn_pages/guards.rs"]
mod guards;
