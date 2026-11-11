//! NAT configuration and paginated runtime reads.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_inline_in_public_items,
    reason = "router reads are not inline candidates"
)]

use kcc_rci::{RciBody, RciPath};
use serde::Serialize;
use serde_json::{Value, json};

use super::model::{ConfiguredRule, NatPage, NatSession};
use crate::{DomainError, Result, RouterCtx};

/// Maximum number of runtime NAT rows requested from the router at once.
pub const PAGE_SIZE: usize = 200;

/// Reads running `ip static` forwarding rules.
// cancel-safe: a single read request; cancellation changes nothing on the router.
pub async fn running_forwards(router: &RouterCtx) -> Result<Vec<ConfiguredRule>> {
    configuration(router, false, "static").await
}

/// Reads startup `ip static` forwarding rules.
// cancel-safe: a single read request; cancellation changes nothing on the router.
pub async fn startup_forwards(router: &RouterCtx) -> Result<Vec<ConfiguredRule>> {
    configuration(router, true, "static").await
}

/// Reads running `ip nat` interface declarations.
// cancel-safe: a single read request; cancellation changes nothing on the router.
pub async fn interfaces(router: &RouterCtx) -> Result<Vec<ConfiguredRule>> {
    configuration(router, false, "nat").await
}

/// Reads one bounded page from `show ip nat`.
// cancel-safe: a single read request; cancellation changes nothing on the router.
pub async fn sessions_page(router: &RouterCtx, offset: usize) -> Result<NatPage> {
    #[derive(Serialize)]
    struct Query {
        offset: usize,
        limit: usize,
    }
    let path = RciPath::from_segments(["show", "ip", "nat"])
        .map_err(|_error| DomainError::InvalidResponse)?;
    let RciBody::Json(response) = router
        .client
        .show(
            &path,
            &Query {
                offset,
                limit: PAGE_SIZE,
            },
        )
        .await?
    else {
        return Err(DomainError::InvalidResponse);
    };
    let rows = serde_json::from_value::<Vec<NatSession>>(response.value)
        .map_err(|_error| DomainError::InvalidResponse)?;
    if rows.len() > PAGE_SIZE {
        return Err(DomainError::InvalidResponse);
    }
    Ok(NatPage { offset, rows })
}

/// Reads one IP configuration collection from running or startup state.
async fn configuration(
    router: &RouterCtx,
    startup: bool,
    leaf: &str,
) -> Result<Vec<ConfiguredRule>> {
    let request = json!({"ip":{leaf:{}}});
    let body = if startup {
        router.client.show_sc(request).await?
    } else {
        router.client.show_rc(request).await?
    };
    let pointer = format!("/ip/{leaf}");
    serde_json::from_value(
        body.configuration_tree()
            .pointer(&pointer)
            .cloned()
            .unwrap_or(Value::Array(Vec::new())),
    )
    .map_err(|_error| DomainError::InvalidResponse)
}
