//! The startup warning of an outbound policy that admits no router network.

use kcc_app::settings::OutboundConfig;

/// Logs one warning when routers exist but the outbound policy names no network.
///
/// With `[outbound] allowed_networks` and `allowed_suffixes` both empty, deny-by-default
/// refuses every router outside loopback until the operator names its network.
pub(crate) fn warn_closed_policy(outbound: &OutboundConfig, routers: usize) {
    if routers > 0 && outbound.allowed_networks.is_empty() && outbound.allowed_suffixes.is_empty() {
        tracing::warn!(
            routers,
            allow_loopback = outbound.allow_loopback,
            "[outbound] allowed_networks and allowed_suffixes are empty, so kcc refuses every router address outside them; add the routers' networks to allowed_networks in kcc.toml"
        );
    }
}
