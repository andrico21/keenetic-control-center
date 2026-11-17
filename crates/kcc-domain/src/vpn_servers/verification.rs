//! Non-secret VPN server configuration expectations.

use kcc_app::workflow::{PresencePredicate, VerificationSpec};
use serde_json::{Value, json};

use super::VpnServerChange;
use crate::pointer;

/// Keeps context names in the read-back identity rather than relying on row order.
pub(super) fn specs(
    change: &VpnServerChange,
    catalog_path: &str,
    body: &Value,
) -> Vec<VerificationSpec> {
    let path = vec!["show".to_owned(), "rc".to_owned()];
    let spec = match change {
        VpnServerChange::Service {
            service: _,
            enabled,
        } => VerificationSpec::collection(
            path,
            "/service".to_owned(),
            json!({"name":catalog_path.strip_prefix("service ").unwrap_or(catalog_path)}),
            *enabled,
        ),
        VpnServerChange::WireGuardInterface { interface, enabled } => VerificationSpec::collection(
            path,
            "/wireguard-server/interface".to_owned(),
            json!({"interface":interface}),
            *enabled,
        ),
        VpnServerChange::IpsecMap { name } => VerificationSpec::presence(
            path,
            format!("/crypto/map/{}", pointer::escape(name)),
            PresencePredicate::Present,
        ),
        VpnServerChange::IpsecVirtualIp { name, enabled } => VerificationSpec::new(
            path,
            format!("/crypto/map/{}/virtual-ip/enable", pointer::escape(name)),
            json!(enabled),
        ),
        VpnServerChange::IpsecVirtualIpPool {
            name,
            begin: _,
            end: _,
            size: _,
        } => VerificationSpec::new(
            path,
            format!("/crypto/map/{}/virtual-ip/range", pointer::escape(name)),
            body.clone(),
        ),
        VpnServerChange::IpsecVirtualIpDns {
            name,
            primary: _,
            secondary: _,
        } => VerificationSpec::new(
            path,
            format!(
                "/crypto/map/{}/virtual-ip/dns-servers",
                pointer::escape(name)
            ),
            body.clone(),
        ),
        VpnServerChange::OpenConnectRoute {
            address: _,
            mask: _,
        } => VerificationSpec::collection(path, "/oc-server/route".to_owned(), body.clone(), true),
        VpnServerChange::VpnInterface { interface: _ }
        | VpnServerChange::VpnPool { begin: _, size: _ }
        | VpnServerChange::VpnDns {
            primary: _,
            secondary: _,
        }
        | VpnServerChange::SstpInterface { interface: _ }
        | VpnServerChange::SstpPool { begin: _, size: _ }
        | VpnServerChange::SstpDns {
            primary: _,
            secondary: _,
        }
        | VpnServerChange::OpenConnectInterface { interface: _ }
        | VpnServerChange::OpenConnectPool { begin: _, size: _ }
        | VpnServerChange::OpenConnectDns {
            primary: _,
            secondary: _,
        } => VerificationSpec::new(
            path,
            format!("/{}", catalog_path.replace(' ', "/")),
            body.clone(),
        ),
    };
    vec![spec]
}
