//! Explicit outbound policies for fixtures and the capture tool.
//!
//! `kcc_rci::OutboundPolicy::default()` admits nothing. Tests and `kcc-capture`, which
//! reach routers on loopback or a private LAN, build these explicit policies instead.

use alloc::sync::Arc;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use kcc_rci::{
    AllowedNetwork, OutboundPolicy, RciClient, RciClientOptions, RciError, RouterUrl, TlsMode,
    auth::Credentials,
    auth_options::Options,
    session::{HttpTimeouts, Manager},
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

/// Builds a bare session manager for `router` under `outbound`, verifying TLS with default
/// timeouts, for tests of the session layer itself.
///
/// # Errors
///
/// Policy, DNS, TLS-provider or HTTP-client construction errors.
// NOT cancel-safe: cancellation can abandon synchronous DNS resolution, but sends no request.
#[inline]
pub async fn connect_manager(
    router: RouterUrl,
    credentials: Credentials,
    outbound: &OutboundPolicy,
) -> Result<Manager, RciError> {
    let timeouts = HttpTimeouts::default();
    let builder = outbound
        .client_builder(&router, &TlsMode::Verify, timeouts)
        .await?;
    Manager::with_client_builder(router, credentials, timeouts, builder)
}

/// Builds a bare session manager like [`connect_manager`] with an explicit authentication policy;
/// `credentials` may be absent for a token-only policy.
///
/// # Errors
///
/// Validation, policy, DNS, TLS-provider or HTTP-client construction errors.
// NOT cancel-safe: cancellation can abandon synchronous DNS resolution, but sends no request.
#[inline]
pub async fn connect_manager_with_options(
    (router, outbound): (RouterUrl, &OutboundPolicy),
    credentials: Option<Credentials>,
    options: Options,
) -> Result<Manager, RciError> {
    let builder = outbound
        .client_builder(&router, &TlsMode::Verify, HttpTimeouts::default())
        .await?;
    Manager::with_options_and_client_builder(router, credentials, options, builder)
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
