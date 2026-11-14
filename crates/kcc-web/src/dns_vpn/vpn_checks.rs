//! How the VPN dialogs' values are checked before anything is sent, and the VPN client
//! or server changes each plans.

use kcc_app::workflow::CliChangeRequest;
use kcc_domain::{
    ChangeOp, DomainError, Result as DomainResult, RouterCtx,
    vpn_clients::{self, VpnClientChange},
    vpn_servers::{self, VpnServerChange},
};
use kcc_i18n::{bundle::MessageKey, keys};

use super::{
    check,
    check::Optional,
    vpn_forms::{Server, VpnForm},
};
use crate::page_kit::{form::Errors, request::Params};

/// Checked VPN changes, ready to plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Planned {
    /// Client changes, in order.
    Clients(Vec<VpnClientChange>),
    /// Server changes, in order.
    Servers(Vec<VpnServerChange>),
}

impl Planned {
    /// The one operation of every change, planned for the router of `ctx`, and its
    /// protected request.
    ///
    /// # Errors
    ///
    /// Returns the catalog's findings.
    pub(crate) async fn request(
        &self,
        ctx: &RouterCtx,
    ) -> DomainResult<(ChangeOp, CliChangeRequest)> {
        let operation = match self {
            Self::Clients(changes) => {
                let mut operation = None;
                for change in changes {
                    merge(&mut operation, vpn_clients::plan_change(ctx, change).await?);
                }
                operation.ok_or(DomainError::InvalidResponse)?
            }
            Self::Servers(changes) => {
                let mut operation = None;
                for change in changes {
                    merge(&mut operation, vpn_servers::plan_change(ctx, change)?);
                }
                operation.ok_or(DomainError::InvalidResponse)?
            }
        };
        let request = match self {
            Self::Clients(_) => vpn_clients::change_request(&operation)?,
            Self::Servers(_) => vpn_servers::change_request(&operation)?,
        };
        Ok((operation, request))
    }
}

/// Merges one complete operation without losing its maximum risk or verification.
fn merge(aggregate: &mut Option<ChangeOp>, mut operation: ChangeOp) {
    if let Some(planned) = aggregate {
        planned.requests.append(&mut operation.requests);
        planned.verify.append(&mut operation.verify);
        planned.risk = planned.risk.max(operation.risk);
        planned.persists_immediately |= operation.persists_immediately;
    } else {
        *aggregate = Some(operation);
    }
}

/// The changes `values` ask for in the dialog `form`, or the field errors that stop them.
///
/// # Errors
///
/// Returns every field whose value is not valid.
pub(crate) fn check(form: VpnForm, values: &Params) -> Result<Planned, Errors> {
    let mut errors = Errors::new();
    let planned = match form {
        VpnForm::Create | VpnForm::Import => created(values, &mut errors),
        VpnForm::Peer => peer(values, &mut errors),
        VpnForm::Pool(server) => {
            let begin = required(
                &mut errors,
                ("begin", keys::WEB_DNS_ERROR_ADDRESS),
                check::ip(values.text("begin")),
            );
            let size = optional(
                &mut errors,
                ("size", keys::WEB_VPN_ERROR_SIZE),
                check::optional_number(values.text("size"), 1),
            );
            Planned::Servers(vec![match server {
                Server::Vpn => VpnServerChange::VpnPool { begin, size },
                Server::Sstp => VpnServerChange::SstpPool { begin, size },
                Server::OpenConnect => VpnServerChange::OpenConnectPool { begin, size },
            }])
        }
        VpnForm::Dns(server) => {
            let primary = required(
                &mut errors,
                ("primary", keys::WEB_DNS_ERROR_ADDRESS),
                check::ip(values.text("primary")),
            );
            let secondary = optional_ip(&mut errors, "secondary", values);
            Planned::Servers(vec![match server {
                Server::Vpn => VpnServerChange::VpnDns { primary, secondary },
                Server::Sstp => VpnServerChange::SstpDns { primary, secondary },
                Server::OpenConnect => VpnServerChange::OpenConnectDns { primary, secondary },
            }])
        }
        VpnForm::Ipsec => ipsec(values, &mut errors),
    };
    if errors.is_empty() {
        Ok(planned)
    } else {
        Err(errors)
    }
}

/// `parsed`, or the field error `(name, error)` recorded in `errors`.
fn required(
    errors: &mut Errors,
    (name, error): (&'static str, MessageKey),
    parsed: Option<String>,
) -> String {
    if parsed.is_none() {
        errors.push((name, error));
    }
    parsed.unwrap_or_default()
}

/// The optional `parsed`, or the field error `(name, error)` recorded in `errors`.
fn optional<T>(
    errors: &mut Errors,
    (name, error): (&'static str, MessageKey),
    parsed: Optional<T>,
) -> Option<T> {
    parsed.unwrap_or_else(|_invalid| {
        errors.push((name, error));
        None
    })
}

/// The optional IP address in the field `name`.
fn optional_ip(errors: &mut Errors, name: &'static str, values: &Params) -> Option<String> {
    let parsed = check::optional(values.text(name), check::ip);
    optional(errors, (name, keys::WEB_DNS_ERROR_ADDRESS), parsed)
}

/// A new WireGuard connection: created, with a router-generated key and the optional port.
fn created(values: &Params, errors: &mut Errors) -> Planned {
    let name = required(
        errors,
        ("name", keys::WEB_VPN_ERROR_NAME),
        check::tunnel(values.text("name")),
    );
    let port = optional(
        errors,
        ("port", keys::WEB_DNS_ERROR_PORT),
        check::port(values.text("port")),
    );
    let mut changes = vec![
        VpnClientChange::Create { name: name.clone() },
        VpnClientChange::GenerateWireGuardPrivateKey { name: name.clone() },
    ];
    if let Some(number) = port {
        changes.push(VpnClientChange::WireGuardListenPort { name, port: number });
    }
    Planned::Clients(changes)
}

/// A WireGuard peer: its key, then the endpoint, allowed ranges and keepalive given.
fn peer(values: &Params, errors: &mut Errors) -> Planned {
    let name = required(
        errors,
        ("tunnel", keys::WEB_VPN_ERROR_NAME),
        check::tunnel(values.text("tunnel")),
    );
    let public_key = required(
        errors,
        ("key", keys::WEB_VPN_ERROR_KEY),
        check::wireguard_key(values.text("key")),
    );
    let parsed = check::optional(values.text("endpoint"), check::endpoint);
    let endpoint = optional(errors, ("endpoint", keys::WEB_VPN_ERROR_ENDPOINT), parsed);
    let ranges = check::ipv4_ranges(values.text("allowed"));
    if ranges.is_none() {
        errors.push(("allowed", keys::WEB_VPN_ERROR_ALLOWED));
    }
    let keepalive = optional(
        errors,
        ("keepalive", keys::WEB_VPN_ERROR_KEEPALIVE),
        check::optional_number(values.text("keepalive"), 1),
    );
    let mut changes = vec![VpnClientChange::WireGuardPeer {
        name: name.clone(),
        public_key: public_key.clone(),
    }];
    if let Some((address, port)) = endpoint {
        changes.push(VpnClientChange::WireGuardEndpoint {
            name: name.clone(),
            public_key: public_key.clone(),
            address,
            port,
        });
    }
    for (address, mask) in ranges.unwrap_or_default() {
        changes.push(VpnClientChange::WireGuardAllowedIp {
            name: name.clone(),
            public_key: public_key.clone(),
            address,
            mask,
        });
    }
    if let Some(seconds) = keepalive {
        changes.push(VpnClientChange::WireGuardKeepalive {
            name,
            public_key,
            seconds,
        });
    }
    Planned::Clients(changes)
}

/// The IPsec/IKEv2 virtual IP settings of one crypto map.
fn ipsec(values: &Params, errors: &mut Errors) -> Planned {
    let name = required(
        errors,
        ("map", keys::WEB_VPN_ERROR_MAP),
        check::object(values.text("map")),
    );
    let enabled = values.text("enabled") != "off";
    let begin = optional_ip(errors, "begin", values);
    let size = optional(
        errors,
        ("size", keys::WEB_VPN_ERROR_SIZE),
        check::optional_number(values.text("size"), 1),
    );
    let primary = optional_ip(errors, "primary", values);
    let secondary = optional_ip(errors, "secondary", values);
    let mut changes = vec![VpnServerChange::IpsecVirtualIp {
        name: name.clone(),
        enabled,
    }];
    match (begin, size) {
        (Some(first), Some(count)) => changes.push(VpnServerChange::IpsecVirtualIpPool {
            name: name.clone(),
            begin: first,
            end: None,
            size: Some(count),
        }),
        (Some(_), None) => errors.push(("size", keys::WEB_VPN_ERROR_SIZE)),
        (None, Some(_)) => errors.push(("begin", keys::WEB_DNS_ERROR_ADDRESS)),
        (None, None) => {}
    }
    match (primary, secondary) {
        (Some(first), second) => changes.push(VpnServerChange::IpsecVirtualIpDns {
            name,
            primary: first,
            secondary: second,
        }),
        (None, Some(_)) => errors.push(("primary", keys::WEB_DNS_ERROR_ADDRESS)),
        (None, None) => {}
    }
    Planned::Servers(changes)
}
