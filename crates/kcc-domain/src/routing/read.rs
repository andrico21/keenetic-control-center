//! Routing-table reads.

use super::model::RouteTableEntry;
use crate::{Result, RouterCtx, read_show};

/// Reads the current IPv4 routing table.
///
/// # Errors
///
/// Returns an error when a router request fails or its reply does not decode
/// ([`crate::DomainError::Rci`], [`crate::DomainError::InvalidResponse`]).
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, a single read request; cancellation changes nothing on the router.
#[inline]
pub async fn ipv4_table(router: &RouterCtx) -> Result<Vec<RouteTableEntry>> {
    read_show(&router.client, &["show", "ip", "route"]).await
}

/// Reads the current IPv6 routing table.
///
/// # Errors
///
/// Returns an error when a router request fails or its reply does not decode
/// ([`crate::DomainError::Rci`], [`crate::DomainError::InvalidResponse`]).
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, a single read request; cancellation changes nothing on the router.
#[inline]
pub async fn ipv6_table(router: &RouterCtx) -> Result<Vec<RouteTableEntry>> {
    read_show(&router.client, &["show", "ipv6", "route"]).await
}
