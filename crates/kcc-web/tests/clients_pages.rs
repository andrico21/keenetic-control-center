//! The clients, DHCP and segments pages against the fake router: what each role sees, a
//! change applied and read back, a value refused before anything is sent, and a router
//! refusal shown in the router's own words.

#[expect(
    dead_code,
    reason = "the shared Web UI test support; this suite needs part of it"
)]
#[path = "support/mod.rs"]
mod support;

/// The table row of `html` that holds `needle`, from its `<tr>` to its `</tr>`.
pub(crate) fn row<'page>(html: &'page str, needle: &str) -> Option<&'page str> {
    let at = html.find(needle)?;
    let start = html.get(..at)?.rfind("<tr>")?;
    let end = at.checked_add(html.get(at..)?.find("</tr>")?)?;
    html.get(start..end)
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "clients_pages/clients.rs"]
mod clients;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "clients_pages/dhcp.rs"]
mod dhcp;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "clients_pages/segments.rs"]
mod segments;
