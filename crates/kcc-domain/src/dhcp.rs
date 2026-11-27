//! DHCP pools, static leases, bindings, and ARP neighbours.

mod command;
pub mod model;

use core::{
    net::Ipv4Addr,
    result::Result as CoreResult,
    str::{FromStr as _, from_utf8},
};

use kcc_app::workflow::{ChangeSet, CliChangeResult, WorkflowError};
use kcc_catalog::ValidationIssue;
use kcc_rci::{ConfigKind, Mac};
use secrecy::ExposeSecret as _;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use self::model::{Binding, Neighbour, Pool, PoolConfig, StaticLease};
use crate::{
    ChangeOp, DomainDescriptor, DomainError, DomainId, OperationDescriptor, Result, RouterCtx,
    cli_token, decode, descriptor, read_show,
};

/// DHCP read inventory.
const READS: &[OperationDescriptor] = &[
    descriptor::read("pools", "ip dhcp pool"),
    descriptor::read("static_leases", "ip dhcp host"),
    descriptor::read("bindings", "show ip dhcp bindings"),
    descriptor::read("neighbours", "show ip arp"),
];

/// DHCP write inventory.
const WRITES: &[OperationDescriptor] = &[
    descriptor::write("pool", "ip dhcp pool"),
    descriptor::write("static_lease", "ip dhcp host"),
];

/// DHCP domain metadata.
pub const DESCRIPTOR: DomainDescriptor = DomainDescriptor {
    id: DomainId::Dhcp,
    read_ops: READS,
    write_ops: WRITES,
    required_components: &[],
};

/// Reads DHCP pools from the running configuration text.
///
/// # Errors
///
/// Returns an error when a router request fails or its reply does not decode
/// ([`DomainError::Rci`], [`DomainError::InvalidResponse`]), or when a reply or a plan
/// does not have the expected shape ([`DomainError::InvalidResponse`]).
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, a single read request; cancellation changes nothing on the router.
#[inline]
pub async fn read_pools(router: &RouterCtx) -> Result<Vec<Pool>> {
    let bytes = router.client.download_config(ConfigKind::Running).await?;
    let text = from_utf8(bytes.expose_secret()).map_err(|_error| DomainError::InvalidResponse)?;
    Ok(model::parse_pools(text))
}

/// Reads running static leases through `show rc ip dhcp host`.
///
/// # Errors
///
/// Returns an error when a router request fails or its reply does not decode
/// ([`DomainError::Rci`], [`DomainError::InvalidResponse`]).
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, a single read request; cancellation changes nothing on the router.
#[inline]
pub async fn read_static_leases(router: &RouterCtx) -> Result<Vec<StaticLease>> {
    let answer = router
        .client
        .show_rc(json!({"ip":{"dhcp":{"host":{}}}}))
        .await?;
    decode_config_rows(router.client.log_id(), &answer, "/ip/dhcp/host")
}

/// Reads current DHCP bindings.
///
/// # Errors
///
/// Returns an error when a router request fails or its reply does not decode
/// ([`DomainError::Rci`], [`DomainError::InvalidResponse`]).
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, a single read request; cancellation changes nothing on the router.
#[inline]
pub async fn read_bindings(router: &RouterCtx) -> Result<Vec<Binding>> {
    read_show(&router.client, &["show", "ip", "dhcp", "bindings"]).await
}

/// Reads current ARP neighbours.
///
/// # Errors
///
/// Returns an error when a router request fails or its reply does not decode
/// ([`DomainError::Rci`], [`DomainError::InvalidResponse`]).
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, a single read request; cancellation changes nothing on the router.
#[inline]
pub async fn read_neighbours(router: &RouterCtx) -> Result<Vec<Neighbour>> {
    read_show(&router.client, &["show", "ip", "arp"]).await
}

/// Plans a complete DHCP pool configuration; the pool name is one router object name, and
/// more than one DNS server is refused before any request.
///
/// # Errors
///
/// Returns an error when an argument cannot be one safe router CLI word
/// ([`DomainError::InvalidCliToken`]), or when the catalog refuses a planned request
/// ([`DomainError::Validation`]).
#[inline]
pub fn plan_pool(router: &RouterCtx, pool: &PoolConfig) -> Result<ChangeOp> {
    let name = cli_token::object_name(&pool.name)?;
    let mut inputs = vec![
        ("ip dhcp pool", json!({"name":name})),
        (
            "ip dhcp pool range",
            json!({"begin":pool.range_begin.to_string(),"end":pool.range_end.to_string()}),
        ),
        (
            "ip dhcp pool default-router",
            json!({"address":pool.default_router.to_string()}),
        ),
        ("ip dhcp pool lease", json!({"lease":pool.lease_seconds})),
        (
            "ip dhcp pool enable",
            if pool.enabled {
                json!({})
            } else {
                json!({"no":true})
            },
        ),
    ];
    match pool.dns_servers.as_deref() {
        None => {}
        Some([]) => inputs.push(("ip dhcp pool dns-server", json!({"no":true}))),
        Some([address]) => inputs.push((
            "ip dhcp pool dns-server",
            json!({"address1":address.to_string()}),
        )),
        Some(_) => {
            return Err(DomainError::Validation {
                issues: vec![ValidationIssue::InvalidValue {
                    field: "dns".to_owned(),
                }],
            });
        }
    }
    if !pool.interface.is_empty() {
        inputs.push(("ip dhcp pool bind", json!({"interface":pool.interface})));
    }
    command::plan(router, &inputs)
}

/// Plans a static lease only after validating the bound pool subnet and duplicate address.
///
/// # Errors
///
/// Returns an error when the lease is outside its pool
/// ([`DomainError::StaticLeaseOutsidePool`]), when the address is leased to another MAC
/// ([`DomainError::StaticLeaseAddressInUse`]), when the catalog refuses a planned request
/// ([`DomainError::Validation`]), or when a router request fails or its reply does not
/// decode ([`DomainError::Rci`], [`DomainError::InvalidResponse`]).
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, only read requests; cancellation changes nothing on the router.
#[inline]
pub async fn plan_static_lease(
    router: &RouterCtx,
    mac: Mac,
    address: Ipv4Addr,
) -> Result<ChangeOp> {
    let lease_mac = mac.to_string();
    let pools = read_pools(router).await?;
    let bindings = read_bindings(router).await?;
    let leases = read_static_leases(router).await?;
    let interfaces: Value = read_show(&router.client, &["show", "interface"]).await?;
    let inside = pools.iter().any(|pool| {
        pool.interface.as_deref().is_some_and(|interface| {
            interface_subnet(&interfaces, interface)
                .is_some_and(|(network, mask)| network == u32::from(address) & mask)
        })
    });
    if !inside {
        return Err(DomainError::StaticLeaseOutsidePool);
    }
    let address_text = address.to_string();
    let assigned_elsewhere = bindings
        .iter()
        .map(|binding| (binding.mac.as_deref(), binding.address.as_deref()))
        .chain(
            leases
                .iter()
                .map(|lease| (lease.mac.as_deref(), lease.address.as_deref())),
        )
        .any(|(assigned_mac, assigned_address)| {
            assigned_address == Some(address_text.as_str())
                && assigned_mac.is_some_and(|value| !value.eq_ignore_ascii_case(&lease_mac))
        });
    if assigned_elsewhere {
        return Err(DomainError::StaticLeaseAddressInUse);
    }
    command::plan(
        router,
        &[(
            "ip dhcp host",
            json!({"host":lease_mac,"ip":address.to_string()}),
        )],
    )
}

/// Executes a DHCP plan through the protected workflow, which reads every line and static
/// lease back before it audits the change.
///
/// # Errors
///
/// Returns an error when the change workflow fails: dispatch, read-back or audit (a
/// [`WorkflowError`]).
// NOT cancel-safe: cancelled after the CLI request is sent, the router stays changed
// and the read-back verification never runs.
#[inline]
pub async fn apply(
    changes: &mut ChangeSet,
    _router: &RouterCtx,
    operation: &ChangeOp,
) -> CoreResult<CliChangeResult, WorkflowError> {
    changes.apply_cli(command::request(operation)?).await
}

/// Decodes the configuration rows at `pointer` of the router logged as `router`.
///
/// # Errors
///
/// Returns an error when `pointer` is absent ([`DomainError::InvalidResponse`]) or its
/// rows do not decode ([`DomainError::UnreadableAnswer`]).
fn decode_config_rows<T>(
    router: &str,
    answer: &kcc_rci::ConfigurationAnswer,
    pointer: &str,
) -> Result<Vec<T>>
where
    T: DeserializeOwned,
{
    let rows = answer
        .configuration_tree()
        .pointer(pointer)
        .ok_or(DomainError::InvalidResponse)?;
    let resource = format!("show rc{}", pointer.replace('/', " "));
    decode::value(router, &resource, rows)
}

/// Returns the network and mask for an interface show row.
fn interface_subnet(interfaces: &Value, interface: &str) -> Option<(u32, u32)> {
    let row = interfaces.get(interface)?;
    let address = Ipv4Addr::from_str(row.get("address")?.as_str()?).ok()?;
    let mask = Ipv4Addr::from_str(row.get("mask")?.as_str()?).ok()?;
    let mask_bits = u32::from(mask);
    Some((u32::from(address) & mask_bits, mask_bits))
}
