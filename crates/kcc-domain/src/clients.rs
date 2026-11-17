//! Connected-client inventory and hotspot controls.

mod command;

use alloc::{collections::BTreeMap, vec};
use core::result::Result as CoreResult;

use kcc_app::workflow::{ChangeSet, CliChangeResult, WorkflowError};
use kcc_catalog::Risk;
use kcc_rci::Mac;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    ChangeOp, DomainDescriptor, DomainError, DomainId, OperationDescriptor, Result, RouterCtx,
    descriptor, read_show,
};

/// Tolerant `show ip hotspot` row.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(default)]
#[non_exhaustive]
pub struct Client {
    /// Client MAC address.
    pub mac: Option<String>,
    /// Current IP address.
    #[serde(alias = "address")]
    pub ip: Option<String>,
    /// Registered host name.
    pub name: Option<String>,
    /// Serving bridge or access point.
    pub interface: Option<String>,
    /// Whether this MAC is a known host.
    pub registered: Option<bool>,
    /// Current permit or deny override.
    pub access: Option<String>,
    /// Assigned connection policy.
    pub policy: Option<String>,
    /// Assigned schedule.
    pub schedule: Option<String>,
    /// Received byte counter.
    pub rx: Option<u64>,
    /// Transmitted byte counter.
    pub tx: Option<u64>,
    /// Link state.
    pub link: Option<String>,
    /// Wireless signal strength in dBm.
    pub rssi: Option<i16>,
    /// Host priority from 1 through 7.
    pub priority: Option<u8>,
    /// Unmodelled router fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Hotspot access decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Access {
    /// Permit network access.
    Permit,
    /// Deny network access.
    Deny,
}

impl Access {
    /// Returns the router CLI keyword.
    const fn keyword(self) -> &'static str {
        match self {
            Self::Permit => "permit",
            Self::Deny => "deny",
        }
    }
}

/// Default or per-interface hotspot policy selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PolicySelection<'value> {
    /// Apply a permit or deny decision.
    Access(Access),
    /// Apply a named connection policy.
    Policy(&'value str),
}

/// The most characters of a router-reported name kept in a registration name.
const NAME_CHARS: usize = 64;

/// Client read inventory.
const READS: &[OperationDescriptor] = &[descriptor::by_risk("list", "show ip hotspot", Risk::Read)];

/// Client write inventory.
const WRITES: &[OperationDescriptor] = &[
    descriptor::by_risk("register", "known host", Risk::Write),
    descriptor::by_risk("remove", "known host", Risk::Write),
    descriptor::by_risk("access", "ip hotspot host", Risk::Write),
    descriptor::by_risk("schedule", "ip hotspot host", Risk::Write),
    descriptor::by_risk("policy", "ip hotspot host", Risk::Write),
    descriptor::by_risk("priority", "ip hotspot host priority", Risk::Write),
    descriptor::by_risk("default_policy", "ip hotspot default-policy", Risk::Write),
    descriptor::by_risk("interface_policy", "ip hotspot policy", Risk::Write),
    descriptor::by_risk("wake", "ip hotspot wake", Risk::Write),
];

/// Clients domain metadata.
pub const DESCRIPTOR: DomainDescriptor = DomainDescriptor {
    id: DomainId::Clients,
    read_ops: READS,
    write_ops: WRITES,
    required_components: &[],
};

/// Reads all connected and remembered clients from `show ip hotspot`.
///
/// # Errors
///
/// Returns an error when a router request fails or its reply does not decode
/// ([`DomainError::Rci`], [`DomainError::InvalidResponse`]).
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, a single read request; cancellation changes nothing on the router.
#[inline]
#[expect(
    clippy::module_name_repetitions,
    reason = "the read is named after the router list it returns, like the reads of the other domain modules"
)]
pub async fn read_clients(router: &RouterCtx) -> Result<Vec<Client>> {
    read_show(&router.client, &["show", "ip", "hotspot"]).await
}

/// Reads one client by MAC address.
///
/// # Errors
///
/// Returns an error when a router request fails or its reply does not decode
/// ([`DomainError::Rci`], [`DomainError::InvalidResponse`]).
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, a single read request; cancellation changes nothing on the router.
#[inline]
pub async fn read_client(router: &RouterCtx, mac: &str) -> Result<Option<Client>> {
    Ok(read_clients(router).await?.into_iter().find(|client| {
        client
            .mac
            .as_deref()
            .is_some_and(|value| value.eq_ignore_ascii_case(mac))
    }))
}

/// Plans registration or rename through `known host <name> <mac>`, the name sent as one
/// quoted word.
///
/// # Errors
///
/// Returns an error when the catalog refuses a planned request
/// ([`DomainError::Validation`]).
#[inline]
pub fn plan_register(router: &RouterCtx, mac: Mac, name: &str) -> Result<ChangeOp> {
    command::plan(
        router,
        &[("known host", json!({"name":name,"mac":mac.to_string()}))],
    )
}

/// The name an unregistered client is registered under when an action needs one: the
/// reported name with every other character replaced by a hyphen, else one made from
/// its MAC address.
#[must_use]
#[inline]
pub fn registration_name(client: &Client) -> String {
    let reported: String = client
        .name
        .as_deref()
        .unwrap_or_default()
        .chars()
        .take(NAME_CHARS)
        .map(|letter| {
            if letter.is_alphanumeric() || matches!(letter, '_' | '.') {
                letter
            } else {
                '-'
            }
        })
        .collect();
    let trimmed = reported.trim_matches('-');
    if trimmed.is_empty() {
        format!(
            "client-{}",
            client.mac.as_deref().unwrap_or_default().replace(':', "")
        )
    } else {
        trimmed.to_owned()
    }
}

/// Plans the only supported host-removal path: `no known host <mac>`.
///
/// # Errors
///
/// Returns an error when the catalog refuses a planned request
/// ([`DomainError::Validation`]).
#[inline]
pub fn plan_remove(router: &RouterCtx, mac: &str) -> Result<ChangeOp> {
    command::plan(router, &[("known host", json!({"mac":mac,"no":true}))])
}

/// Plans a permit or deny override, registering an unknown client first in the same operation.
///
/// # Errors
///
/// Returns an error when the catalog refuses a planned request
/// ([`DomainError::Validation`]).
#[inline]
pub fn plan_access(
    router: &RouterCtx,
    client: &Client,
    name: &str,
    access: Access,
) -> Result<ChangeOp> {
    plan_host_field(router, client, name, json!({"access":access.keyword()}))
}

/// Plans a client schedule, registering an unknown client first in the same operation.
///
/// # Errors
///
/// Returns an error when the catalog refuses a planned request
/// ([`DomainError::Validation`]).
#[inline]
pub fn plan_schedule(
    router: &RouterCtx,
    client: &Client,
    name: &str,
    schedule: &str,
) -> Result<ChangeOp> {
    plan_host_field(router, client, name, json!({"schedule":schedule}))
}

/// Plans a client policy, registering an unknown client first in the same operation.
///
/// # Errors
///
/// Returns an error when the catalog refuses a planned request
/// ([`DomainError::Validation`]).
#[inline]
pub fn plan_policy(
    router: &RouterCtx,
    client: &Client,
    name: &str,
    policy: &str,
) -> Result<ChangeOp> {
    plan_host_field(router, client, name, json!({"policy":policy}))
}

/// Plans client priority, registering an unknown client first in the same operation.
///
/// # Errors
///
/// Returns an error when the catalog refuses a planned request
/// ([`DomainError::Validation`]), or when a reply or a plan does not have the expected
/// shape ([`DomainError::InvalidResponse`]).
#[inline]
pub fn plan_priority(
    router: &RouterCtx,
    client: &Client,
    name: &str,
    priority: u8,
) -> Result<ChangeOp> {
    let mac = client.mac.as_deref().ok_or(DomainError::InvalidResponse)?;
    let mut inputs = registration(client, name, mac);
    inputs.push((
        "ip hotspot host priority",
        json!({"mac":mac,"priority":priority.to_string()}),
    ));
    command::plan(router, &inputs)
}

/// Plans the default hotspot policy.
///
/// # Errors
///
/// Returns an error when the catalog refuses a planned request
/// ([`DomainError::Validation`]).
#[inline]
pub fn plan_default_policy(router: &RouterCtx, selection: PolicySelection<'_>) -> Result<ChangeOp> {
    command::plan(
        router,
        &[("ip hotspot default-policy", selection_body(selection))],
    )
}

/// Plans the hotspot policy for one interface.
///
/// # Errors
///
/// Returns an error when the catalog refuses a planned request
/// ([`DomainError::Validation`]), or when a reply or a plan does not have the expected
/// shape ([`DomainError::InvalidResponse`]).
#[inline]
pub fn plan_interface_policy(
    router: &RouterCtx,
    interface: &str,
    selection: PolicySelection<'_>,
) -> Result<ChangeOp> {
    let mut body = selection_body(selection);
    let fields = body.as_object_mut().ok_or(DomainError::InvalidResponse)?;
    drop(fields.insert("interface".to_owned(), Value::String(interface.to_owned())));
    command::plan(router, &[("ip hotspot policy", body)])
}

/// Plans Wake-on-LAN for one client MAC.
///
/// # Errors
///
/// Returns an error when the catalog refuses a planned request
/// ([`DomainError::Validation`]).
#[inline]
pub fn plan_wake(router: &RouterCtx, mac: &str) -> Result<ChangeOp> {
    command::plan(router, &[("ip hotspot wake", json!({"mac":mac}))])
}

/// Executes a client plan through the protected workflow, which reads host mutations back
/// from `show ip hotspot` (authoritative for registered names) before it audits them.
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

/// Plans one host field with registration first when needed.
///
/// # Errors
///
/// Returns an error when the catalog refuses a planned request
/// ([`DomainError::Validation`]), or when a reply or a plan does not have the expected
/// shape ([`DomainError::InvalidResponse`]).
fn plan_host_field(
    router: &RouterCtx,
    client: &Client,
    name: &str,
    field: Value,
) -> Result<ChangeOp> {
    let mac = client.mac.as_deref().ok_or(DomainError::InvalidResponse)?;
    let mut inputs = registration(client, name, mac);
    let mut body = field;
    let fields = body.as_object_mut().ok_or(DomainError::InvalidResponse)?;
    drop(fields.insert("mac".to_owned(), Value::String(mac.to_owned())));
    inputs.push(("ip hotspot host", body));
    command::plan(router, &inputs)
}

/// Adds registration only for clients not already known to the router.
fn registration<'value>(
    client: &Client,
    name: &'value str,
    mac: &'value str,
) -> Vec<(&'static str, Value)> {
    if client.registered == Some(true) {
        Vec::new()
    } else {
        vec![("known host", json!({"name":name,"mac":mac}))]
    }
}

/// Converts a policy selection to catalog arguments.
fn selection_body(selection: PolicySelection<'_>) -> Value {
    match selection {
        PolicySelection::Access(access) => json!({"access":access.keyword()}),
        PolicySelection::Policy(policy) => json!({"policy":policy}),
    }
}
