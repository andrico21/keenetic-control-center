//! Routing-table reads.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_inline_in_public_items,
    reason = "asynchronous router reads are not inline candidates"
)]

use super::model::RouteTableEntry;
use crate::{Result, RouterCtx, read_show};

/// Reads the current IPv4 routing table.
pub async fn ipv4_table(router: &RouterCtx) -> Result<Vec<RouteTableEntry>> {
    read_show(&router.client, &["show", "ip", "route"]).await
}

/// Reads the current IPv6 routing table.
pub async fn ipv6_table(router: &RouterCtx) -> Result<Vec<RouteTableEntry>> {
    read_show(&router.client, &["show", "ipv6", "route"]).await
}
