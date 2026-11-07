//! `kcc_nat_write` and `kcc_firewall_write`.

use kcc_domain::{
    ChangeOp, DomainError, RouterCtx,
    firewall::{
        change::{self as firewall_change, RuleProperty},
        model::{Action, Direction, Protocol as RuleProtocol, Rule},
    },
    nat::{
        change as nat_change,
        model::{PortForward, Protocol},
    },
};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::Value;

use super::common::{applied, begin, check_op, confirm_risk, needed, open, text};
use crate::{
    KccMcp, McpFailure,
    domains::table::Area,
    support::{errors::map_domain, route::parse},
};

/// NAT write operations.
pub(super) const NAT_OPS: &[&str] = &["forward", "interface"];

/// Firewall write operations.
pub(super) const FIREWALL_OPS: &[&str] = &["rule", "binding"];

/// A transport protocol.
#[derive(Debug, Clone, Copy, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(super) enum Transport {
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
    /// TCP and UDP (port forwards only).
    TcpUdp,
    /// ICMP.
    Icmp,
    /// Any IP protocol (access lists only).
    Ip,
}

/// An access-list rule verdict.
#[derive(Debug, Clone, Copy, Default, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(super) enum Verdict {
    /// Accept matching traffic.
    #[default]
    Permit,
    /// Reject matching traffic.
    Deny,
}

/// Arguments of `kcc_nat_write`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct NatInput {
    /// Router profile id.
    host: String,
    /// Write operation.
    op: String,
    /// Unused confirmation flag accepted for a uniform interface.
    #[serde(default)]
    confirm: bool,
    /// Ingress interface.
    interface: String,
    /// Removes the forward or NAT interface instead of adding it.
    #[serde(default)]
    remove: bool,
    /// Forward protocol.
    #[serde(default)]
    protocol: Option<Transport>,
    /// External port.
    #[serde(default)]
    port: Option<u16>,
    /// Internal IPv4 address.
    #[serde(default)]
    address: Option<String>,
    /// Translated internal port.
    #[serde(default)]
    to_port: Option<u16>,
}

/// Arguments of `kcc_firewall_write`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct FirewallInput {
    /// Router profile id.
    host: String,
    /// Write operation.
    op: String,
    /// Unused confirmation flag accepted for a uniform interface.
    #[serde(default)]
    confirm: bool,
    /// Access-list name.
    acl: String,
    /// Removes the rule or binding instead of adding it.
    #[serde(default)]
    remove: bool,
    /// Rule verdict, `permit` by default.
    #[serde(default)]
    verdict: Verdict,
    /// Rule protocol.
    #[serde(default)]
    protocol: Option<Transport>,
    /// Source address.
    #[serde(default)]
    source: Option<String>,
    /// Destination address.
    #[serde(default)]
    destination: Option<String>,
    /// Destination port.
    #[serde(default)]
    port: Option<u16>,
    /// Rule index for a description or schedule property.
    #[serde(default)]
    index: Option<u32>,
    /// Rule description or schedule name for an indexed rule.
    #[serde(default)]
    description: Option<String>,
    /// Interface for `binding`.
    #[serde(default)]
    interface: Option<String>,
    /// Binds outbound traffic instead of inbound.
    #[serde(default)]
    outbound: bool,
}

/// Runs one NAT write.
pub(super) async fn nat(server: &KccMcp, arguments: Value) -> Result<Value, McpFailure> {
    let input: NatInput = parse(arguments)?;
    check_op(NAT_OPS, &input.op)?;
    let opened = open(
        server,
        Area::Nat,
        (input.host.clone(), &input.op, input.confirm),
    )
    .await?;
    let ctx = &opened.2;
    let interface = text(Some(&input.interface))?;
    let operation = if input.op == "interface" {
        if input.remove {
            nat_change::plan_remove_interface(ctx, interface)
        } else {
            nat_change::plan_add_interface(ctx, interface)
        }
    } else {
        let protocol = match needed(input.protocol)? {
            Transport::Tcp => Protocol::Tcp,
            Transport::Udp => Protocol::Udp,
            Transport::TcpUdp => Protocol::TcpUdp,
            Transport::Icmp => Protocol::Icmp,
            Transport::Ip => return Err(McpFailure::InvalidArguments),
        };
        let mut rule = PortForward::to_address(
            protocol,
            interface,
            needed(input.port)?,
            text(input.address.as_deref())?,
        );
        rule.to_port = input.to_port;
        if input.remove {
            nat_change::plan_remove_forward(ctx, &rule)
        } else {
            nat_change::plan_add_forward(ctx, &rule)
        }
    }
    .map_err(map_domain)?;
    confirm_risk(server, operation.risk, input.confirm)?;
    let mut changes = begin(server, &opened).await?;
    let result = nat_change::apply(&mut changes, ctx, &operation)
        .await
        .map_err(map_domain)?;
    Ok(applied(result.unsaved))
}

/// Plans one firewall change.
fn plan_firewall(
    ctx: &RouterCtx,
    input: &FirewallInput,
) -> Result<Result<ChangeOp, DomainError>, McpFailure> {
    let acl = text(Some(&input.acl))?;
    if input.op == "binding" {
        let direction = if input.outbound {
            Direction::Out
        } else {
            Direction::In
        };
        return Ok(firewall_change::plan_bind(
            ctx,
            text(input.interface.as_deref())?,
            acl,
            direction,
            !input.remove,
        ));
    }
    if let Some(index) = input.index {
        let property = match input.description.as_deref() {
            Some(description) => RuleProperty::Description(text(Some(description))?),
            None => RuleProperty::Disable,
        };
        return Ok(firewall_change::plan_rule_property(
            ctx, acl, index, property,
        ));
    }
    let protocol = match needed(input.protocol)? {
        Transport::Tcp => RuleProtocol::Tcp,
        Transport::Udp => RuleProtocol::Udp,
        Transport::Icmp => RuleProtocol::Icmp,
        Transport::Ip => RuleProtocol::Ip,
        Transport::TcpUdp => return Err(McpFailure::InvalidArguments),
    };
    let action = match input.verdict {
        Verdict::Permit => Action::Permit,
        Verdict::Deny => Action::Deny,
    };
    let mut rule = Rule::new(
        action,
        protocol,
        text(input.source.as_deref())?,
        text(input.destination.as_deref())?,
    );
    rule.destination_port = input.port;
    Ok(if input.remove {
        firewall_change::plan_remove_rule(ctx, acl, &rule)
    } else {
        firewall_change::plan_add_rule(ctx, acl, &rule)
    })
}

/// Runs one firewall write.
pub(super) async fn firewall(server: &KccMcp, arguments: Value) -> Result<Value, McpFailure> {
    let input: FirewallInput = parse(arguments)?;
    check_op(FIREWALL_OPS, &input.op)?;
    let opened = open(
        server,
        Area::Firewall,
        (input.host.clone(), &input.op, input.confirm),
    )
    .await?;
    let operation = plan_firewall(&opened.2, &input)?.map_err(map_domain)?;
    confirm_risk(server, operation.risk, input.confirm)?;
    let mut changes = begin(server, &opened).await?;
    let result = firewall_change::apply(&mut changes, &opened.2, &operation)
        .await
        .map_err(map_domain)?;
    Ok(applied(result.unsaved))
}
