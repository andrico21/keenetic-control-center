//! Explicit outbound policies for fixtures and the capture tool.
//!
//! `kcc_rci::OutboundPolicy::default()` admits nothing. Tests and `kcc-capture`, which
//! reach routers on loopback or a private LAN, build these explicit policies instead.

use alloc::sync::Arc;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use kcc_rci::{
    AllowedNetwork, OutboundPolicy, RciClient, RciClientOptions, RciError, RouterUrl,
    auth::Credentials,
};

/// Connects a client whose policy admits loopback only, for fixtures on `127.0.0.1`.
///
/// # Errors
///
/// Validation, policy or transport errors.
// NOT cancel-safe: cancellation can abandon synchronous DNS resolution, but sends no request.
#[inline]
pub async fn loopback_client(
    router: RouterUrl,
    credentials: Credentials,
) -> Result<Arc<RciClient>, RciError> {
    let options =
        RciClientOptions::default().with_outbound(OutboundPolicy::default().with_loopback(true));
    Ok(Arc::new(
        RciClient::connect_with(router, credentials, options).await?,
    ))
}

/// Private, carrier-grade NAT and unique-local networks plus the Keenetic and Netcraze
/// cloud suffixes; loopback stays refused unless the caller adds it.
#[inline]
#[must_use]
pub fn lan_policy() -> OutboundPolicy {
    let networks = [
        (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8),
        (IpAddr::V4(Ipv4Addr::new(172, 16, 0, 0)), 12),
        (IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)), 16),
        (IpAddr::V4(Ipv4Addr::new(100, 64, 0, 0)), 10),
        (IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0)), 8),
    ]
    .into_iter()
    .filter_map(|(address, prefix_len)| AllowedNetwork::new(address, prefix_len).ok())
    .collect();
    let suffixes = [
        ".keenetic.pro",
        ".keenetic.link",
        ".keenetic.name",
        ".keenetic.io",
        ".keenetic.net",
        // UNVERIFIED: published Netcraze cloud suffixes need live confirmation.
        ".netcraze.pro",
        ".netcraze.link",
        ".netcraze.io",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    OutboundPolicy::default()
        .with_allowed_networks(networks)
        .with_allowed_suffixes(suffixes)
}
