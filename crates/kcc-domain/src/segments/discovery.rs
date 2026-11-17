//! Persisted segment ownership and typed discovery from running configuration.

use core::net::Ipv4Addr;

use kcc_config::config_text::{Ast, Token};
use serde::{Deserialize, Serialize};

use super::{SegmentSpec, ownership, step};
use crate::{DomainError, Result, RouterCtx, config_tree};

/// A validated IEEE 802.1Q VLAN identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[non_exhaustive]
pub struct VlanId(u16);

impl VlanId {
    /// Validates the usable VLAN range.
    ///
    /// # Errors
    ///
    /// Returns an error when an argument cannot be one safe router CLI word
    /// ([`DomainError::InvalidCliToken`]).
    #[inline]
    pub fn new(value: u16) -> Result<Self> {
        if !(1..=4094).contains(&value) {
            return Err(DomainError::InvalidCliToken);
        }
        Ok(Self(value))
    }
    /// Returns the VLAN number.
    #[must_use]
    #[inline]
    pub const fn value(self) -> u16 {
        self.0
    }
}

/// A discovered segment whose ownership survives a new process or router context.
#[derive(Clone, Debug, Serialize)]
#[non_exhaustive]
#[expect(
    clippy::partial_pub_fields,
    reason = "display fields are public while deletion ownership must not be caller-editable"
)]
pub struct SegmentView {
    /// Stable segment suffix.
    pub id: u16,
    /// Validated VLAN number.
    pub vlan_id: VlanId,
    /// Bridge identifier.
    pub bridge: String,
    /// Configured bridge address when present.
    pub address: Option<Ipv4Addr>,
    /// Configured mask when present.
    pub mask: Option<Ipv4Addr>,
    /// DHCP range when present.
    pub dhcp_range: Option<(Ipv4Addr, Ipv4Addr)>,
    /// Whether NAT is configured.
    pub nat: bool,
    /// Whether the domain's hotspot permit policy is configured.
    pub hotspot_policy: bool,
    /// Ports currently carrying the VLAN trunk.
    pub trunked_ports: Vec<String>,
    /// Optional access point binding when present.
    pub access_point: Option<String>,
    /// Optional connection policy when present.
    pub connection_policy: Option<String>,
    /// Whether all recorded steps are present.
    pub complete: bool,
    /// Private immutable ownership record used for deletion.
    #[serde(skip)]
    record: Ownership,
}

/// Deletion scope suitable for a confirmation dialog.
#[derive(Clone, Debug, Serialize)]
#[non_exhaustive]
pub struct DeleteSummary {
    /// Segment identifier.
    pub id: u16,
    /// Contexts created by this domain, including newly introduced trunk contexts.
    pub owned_contexts: Vec<String>,
    /// Existing ports whose segment trunk leaf is removed but whose context remains.
    pub preserved_ports: Vec<String>,
}

/// Serialized intent contains no credentials and is stored in the owned VLAN description.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Ownership {
    /// Original validated segment specification.
    spec: SegmentSpec,
    /// Trunk contexts absent before creation.
    cleanup: Vec<String>,
}

impl SegmentView {
    /// Summarizes only the recorded owned contexts and shared port leaves.
    #[must_use]
    #[inline]
    pub fn delete_summary(&self) -> DeleteSummary {
        let mut owned_contexts = vec![
            format!("interface Vlan{}", self.id),
            format!("interface Bridge{}", self.id),
            format!("ip dhcp pool Pool{}", self.id),
        ];
        owned_contexts.extend(self.record.cleanup.iter().cloned());
        if let Some(policy) = &self.record.spec.connection_policy {
            owned_contexts.push(format!("ip policy {policy}"));
        }
        DeleteSummary {
            id: self.id,
            owned_contexts,
            preserved_ports: self
                .record
                .spec
                .switch_ports
                .iter()
                .filter(|port| !self.record.cleanup.contains(&format!("interface {port}")))
                .cloned()
                .collect(),
        }
    }

    /// Classifies the exact generated deletion plan for this immutable ownership record.
    ///
    /// # Errors
    ///
    /// Returns an error when an identifier cannot be one safe router CLI word
    /// ([`DomainError::InvalidCliToken`]), when the catalog refuses a planned request
    /// ([`DomainError::Validation`]), or when the interface topology needed to classify the
    /// plan cannot be read or does not decode ([`DomainError::Rci`],
    /// [`DomainError::InvalidResponse`]).
    // cancel-safe: management classification performs read-only topology requests.
    #[inline]
    pub async fn deletion_plan(&self, router: &RouterCtx) -> Result<crate::ChangeOp> {
        super::plan_delete(router, &self.record.spec).await
    }

    /// Returns the private creation intent for the shared step definition.
    pub(super) const fn spec(&self) -> &SegmentSpec {
        &self.record.spec
    }

    /// Requires unchanged private ownership facts before accepting a confirmation.
    pub(super) fn same_ownership(&self, other: &Self) -> bool {
        self.record == other.record
    }

    /// Restores only persisted cleanup ownership.
    pub(super) fn steps(&self) -> Vec<step::Step> {
        let mut definitions = step::steps(&self.record.spec);
        for definition in &mut definitions {
            definition.restore_cleanup(&self.record.cleanup);
        }
        definitions
    }
}

/// Validates ownership before creation and prepares the description marker.
///
/// # Errors
///
/// Returns an error when an identifier cannot be one safe router CLI word
/// ([`DomainError::InvalidCliToken`]), or when the running configuration cannot be read
/// (a failed router request is reported this way, not as [`DomainError::Rci`]), already
/// holds the segment's contexts or shared leaves, or the record cannot be serialized
/// ([`DomainError::InvalidResponse`]).
pub(super) async fn prepare(router: &RouterCtx, spec: &SegmentSpec) -> Result<String> {
    ownership::validate(spec)?;
    let tree = step::running_config(router)
        .await
        .map_err(|_error| DomainError::InvalidResponse)?;
    ownership::check_baseline(spec, &tree)?;
    let mut contexts = vec![
        format!("interface Vlan{}", spec.id),
        format!("interface Bridge{}", spec.id),
        format!("ip dhcp pool Pool{}", spec.id),
    ];
    if let Some(policy) = &spec.connection_policy {
        contexts.push(format!("ip policy {policy}"));
    }
    if contexts
        .iter()
        .any(|context| config_tree::context_has_child(&tree, context, None))
    {
        return Err(DomainError::InvalidResponse);
    }
    let cleanup = spec
        .switch_ports
        .iter()
        .map(|port| format!("interface {port}"))
        .filter(|context| !config_tree::context_has_child(&tree, context, None))
        .collect();
    serde_json::to_string(&Ownership {
        spec: spec.clone(),
        cleanup,
    })
    .map(|body| format!("kcc-segment:{body}"))
    .map_err(|_error| DomainError::InvalidResponse)
}

/// Discovers only contexts carrying the domain's persisted ownership marker; a record that
/// cannot be decoded is skipped and logged by its line number, never by its text.
///
/// # Errors
///
/// Returns [`DomainError::InvalidResponse`] when the running configuration cannot be read or
/// parsed; a failing router request is reported this way, not as [`DomainError::Rci`].
/// Ownership records that do not decode are skipped, not reported.
pub(super) async fn read(router: &RouterCtx) -> Result<Vec<SegmentView>> {
    let tree = step::running_config(router)
        .await
        .map_err(|_error| DomainError::InvalidResponse)?;
    let mut result = Vec::new();
    for (context, child) in config_tree::nested(&tree) {
        let words = config_tree::texts(&child.tokens);
        let Some((&"description", rest)) = words.split_first() else {
            continue;
        };
        let description = rest.join(" ");
        let Some(body) = description.strip_prefix("kcc-segment:") else {
            continue;
        };
        match decode(&context.tokens, body, &tree) {
            Ok(view) => result.push(view),
            Err(_error) => tracing::warn!(
                line = child.line_no,
                "skipped an invalid segment ownership record"
            ),
        }
    }
    Ok(result)
}

/// Decodes one ownership record found under `context` into its current view.
///
/// # Errors
///
/// Returns an error when the record does not parse, names contexts it does not own, or
/// does not belong to its VLAN context ([`DomainError::InvalidResponse`]), or when an
/// identifier in it cannot be one safe router CLI word ([`DomainError::InvalidCliToken`]).
fn decode(context: &[Token], body: &str, tree: &Ast) -> Result<SegmentView> {
    let record: Ownership =
        serde_json::from_str(body).map_err(|_error| DomainError::InvalidResponse)?;
    ownership::validate(&record.spec)?;
    if record.cleanup.iter().any(|cleanup_context| {
        !record
            .spec
            .switch_ports
            .iter()
            .any(|port| cleanup_context == &format!("interface {port}"))
    }) {
        return Err(DomainError::InvalidResponse);
    }
    if context != config_tree::command(&format!("interface Vlan{}", record.spec.id)) {
        return Err(DomainError::InvalidResponse);
    }
    project(record, tree)
}

/// Projects current presence separately from persisted intent so partial segments remain visible.
///
/// # Errors
///
/// Returns [`DomainError::InvalidCliToken`] when the record's VLAN id is outside 1 to 4094.
fn project(record: Ownership, tree: &Ast) -> Result<SegmentView> {
    let spec = &record.spec;
    let bridge = format!("Bridge{}", spec.id);
    let has =
        |context: &str, child: &str| config_tree::context_has_child(tree, context, Some(child));
    let addressed = has(
        &format!("interface {bridge}"),
        &format!("ip address {} {}", spec.address, spec.mask),
    );
    let pooled = has(
        &format!("ip dhcp pool Pool{}", spec.id),
        &format!("range {} {}", spec.dhcp_begin, spec.dhcp_end),
    );
    let nat = config_tree::context_has_child(tree, &format!("ip nat {bridge}"), None);
    let hotspot_policy =
        config_tree::context_has_child(tree, &format!("ip hotspot policy {bridge} permit"), None);
    let trunked_ports = spec
        .switch_ports
        .iter()
        .filter(|port| {
            has(
                &format!("interface {port}"),
                &format!("switchport trunk vlan {}", spec.vlan_id),
            )
        })
        .cloned()
        .collect::<Vec<_>>();
    let access_point = spec
        .access_point
        .as_ref()
        .filter(|ap| has(&format!("interface {bridge}"), &format!("include {ap}")))
        .cloned();
    let connection_policy = spec
        .connection_policy
        .as_ref()
        .filter(|policy| has(&format!("ip policy {policy}"), "description segment"))
        .cloned();
    let complete = addressed
        && pooled
        && nat
        && hotspot_policy
        && trunked_ports.len() == spec.switch_ports.len()
        && access_point == spec.access_point
        && connection_policy == spec.connection_policy
        && has(
            &format!("interface {bridge}"),
            &format!("include Vlan{}", spec.id),
        )
        && has(
            &format!("interface Vlan{}", spec.id),
            &format!("vlan-id {}", spec.vlan_id),
        );
    Ok(SegmentView {
        id: spec.id,
        vlan_id: VlanId::new(spec.vlan_id)?,
        bridge,
        address: addressed.then_some(spec.address),
        mask: addressed.then_some(spec.mask),
        dhcp_range: pooled.then_some((spec.dhcp_begin, spec.dhcp_end)),
        nat,
        hotspot_policy,
        trunked_ports,
        access_point,
        connection_policy,
        complete,
        record,
    })
}
