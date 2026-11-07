//! Firewall configuration and UPnP reads.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_inline_in_public_items,
    reason = "router reads are not inline candidates"
)]

use kcc_rci::RciBody;
use serde_json::{Value, json};

use super::model::UpnpRedirect;
use crate::{DomainError, Result, RouterCtx, read_show};

/// Reads named IPv4 access lists from the running configuration.
pub async fn access_lists(router: &RouterCtx) -> Result<Value> {
    let RciBody::Json(response) = router.client.show_rc(json!({"access-list":{}})).await? else {
        return Err(DomainError::InvalidResponse);
    };
    response
        .value
        .pointer("/show/rc/access-list")
        .cloned()
        .ok_or(DomainError::InvalidResponse)
}

/// Reads UPnP-created redirects.
pub async fn upnp_redirects(router: &RouterCtx) -> Result<Vec<UpnpRedirect>> {
    read_show(&router.client, &["show", "upnp", "redirect"]).await
}

/// Returns whether this router catalog exposes IPv6 access lists.
#[inline]
#[must_use]
pub fn ipv6_available(router: &RouterCtx) -> bool {
    router.catalog.lookup("ipv6 access-list").is_some()
}
