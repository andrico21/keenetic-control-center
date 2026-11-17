//! NAT configuration and paginated runtime reads.

use kcc_rci::{RciBody, RciPath};
use serde::Serialize;
use serde_json::{Value, json};

use super::model::{ConfiguredRule, NatPage, NatSession};
use crate::{DomainError, Result, RouterCtx};

/// Maximum number of runtime NAT rows requested from the router at once.
pub const PAGE_SIZE: usize = 200;

/// Reads running `ip static` forwarding rules.
///
/// # Errors
///
/// Returns [`DomainError::Rci`] when the request for the running configuration fails, and
/// [`DomainError::InvalidResponse`] when its `ip static` entries do not decode as forwarding
/// rules; a configuration without such entries gives an empty list.
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, a single read request; cancellation changes nothing on the router.
#[inline]
pub async fn running_forwards(router: &RouterCtx) -> Result<Vec<ConfiguredRule>> {
    configuration(router, false, "static").await
}

/// Reads startup `ip static` forwarding rules.
///
/// # Errors
///
/// Returns [`DomainError::Rci`] when the request for the startup configuration fails, and
/// [`DomainError::InvalidResponse`] when its `ip static` entries do not decode as forwarding
/// rules; a configuration without such entries gives an empty list.
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, a single read request; cancellation changes nothing on the router.
#[inline]
pub async fn startup_forwards(router: &RouterCtx) -> Result<Vec<ConfiguredRule>> {
    configuration(router, true, "static").await
}

/// Reads running `ip nat` interface declarations.
///
/// # Errors
///
/// Returns [`DomainError::Rci`] when the request for the running configuration fails, and
/// [`DomainError::InvalidResponse`] when its `ip nat` entries do not decode as interface
/// declarations; a configuration without such entries gives an empty list.
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, a single read request; cancellation changes nothing on the router.
#[inline]
pub async fn interfaces(router: &RouterCtx) -> Result<Vec<ConfiguredRule>> {
    configuration(router, false, "nat").await
}

/// Reads one bounded page from `show ip nat`.
///
/// # Errors
///
/// Returns an error when a reply or a plan does not have the expected shape
/// ([`DomainError::InvalidResponse`]).
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, a single read request; cancellation changes nothing on the router.
#[inline]
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
///
/// # Errors
///
/// Returns an error when a router request fails or its reply does not decode
/// ([`DomainError::Rci`], [`DomainError::InvalidResponse`]), or when a reply or a plan
/// does not have the expected shape ([`DomainError::InvalidResponse`]).
// NOT cancel-safe: it only reads the running or startup configuration, but it may sign in first,
// and a sign-in dropped mid-way can leave an orphaned router session.
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
