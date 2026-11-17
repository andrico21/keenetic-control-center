//! The interface carrying kcc's management connection to a router.

use core::net::IpAddr;

use kcc_rci::RciClient;
use serde_json::Value;

use crate::inventory::interface_kind;

/// Names the interface whose address kcc reaches the router at.
///
/// The interface comes from the `show interface` reply `interfaces` and the address from
/// the addresses `client` is pinned to; `None` when no interface holds it, for example
/// behind NAT or a port forward.
pub(crate) fn carrying_interface(client: &RciClient, interfaces: &Value) -> Option<String> {
    let hosts = client
        .pinned_addresses()
        .map(|address| address.to_canonical())
        .collect::<Vec<_>>();
    interfaces
        .as_object()?
        .iter()
        .find(|(_name, interface)| {
            interface
                .get("address")
                .and_then(Value::as_str)
                .and_then(|address| address.split('/').next()?.parse::<IpAddr>().ok())
                .is_some_and(|address| hosts.contains(&address.to_canonical()))
        })
        .map(|(name, _interface)| name.clone())
}

/// Whether a line about interface `name` may touch the management connection: `name` is the
/// interface carrying it, or, when that interface is unknown, `name` is any bridge.
pub(crate) fn may_carry(management_interface: Option<&str>, name: &str) -> bool {
    management_interface.map_or_else(
        || interface_kind(name) == "Bridge",
        |current| current == name,
    )
}
