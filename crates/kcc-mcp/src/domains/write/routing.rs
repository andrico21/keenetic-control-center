//! `kcc_routing_write` and `kcc_policies_write`.

use kcc_domain::{
    ChangeOp, DomainError, RouterCtx,
    policies::{
        change::{apply::apply as apply_policy, plan as policy},
        model::{PolicyPermit, PolicyRateLimit, PolicyRoute, RateDirection},
    },
    routing::{
        change as route_change,
        model::{Ipv4Route, Ipv6Route},
    },
};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::Value;

use super::common::{applied, apply, apply_cli, check_op, open, text};
use crate::{
    KccMcp, McpFailure,
    domains::table::Area,
    support::{errors::map_domain, route::parse},
};

/// Routing write operations.
pub(super) const ROUTING_OPS: &[&str] = &["ipv4_route", "ipv6_route"];

/// Policy write operations.
pub(super) const POLICY_OPS: &[&str] = &[
    "policy",
    "description",
    "permit",
    "multipath",
    "route",
    "rate_limit_input",
    "rate_limit_output",
    "standalone",
];

/// Arguments of `kcc_routing_write`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct RouteInput {
    /// Router profile id.
    host: String,
    /// Write operation.
    op: String,
    /// Confirms a management change.
    #[serde(default)]
    confirm: bool,
    /// Destination network (IPv4) or prefix (IPv6), or `default`.
    destination: String,
    /// IPv4 network mask.
    #[serde(default)]
    mask: Option<String>,
    /// Next-hop address.
    #[serde(default)]
    gateway: Option<String>,
    /// Egress interface.
    #[serde(default)]
    interface: Option<String>,
    /// IPv4 route metric.
    #[serde(default)]
    metric: Option<u32>,
    /// Removes the route instead of adding it (guarded against router-wide clears).
    #[serde(default)]
    remove: bool,
}

/// Arguments of `kcc_policies_write`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct PolicyInput {
    /// Router profile id.
    host: String,
    /// Write operation.
    op: String,
    /// Confirms a management change.
    #[serde(default)]
    confirm: bool,
    /// Policy name.
    name: String,
    /// Adds (default) or removes the setting.
    #[serde(default = "enabled_default")]
    enabled: bool,
    /// Description text.
    #[serde(default)]
    description: Option<String>,
    /// Interface for `permit`, `route`, and rate limits.
    #[serde(default)]
    interface: Option<String>,
    /// Permit order, or a fixed rate limit.
    #[serde(default)]
    number: Option<u32>,
    /// Route destination.
    #[serde(default)]
    destination: Option<String>,
    /// Route mask; absent for a host route through `gateway`.
    #[serde(default)]
    mask: Option<String>,
    /// Host-route gateway.
    #[serde(default)]
    gateway: Option<String>,
}

/// Settings are added unless the caller asks for removal.
const fn enabled_default() -> bool {
    true
}

/// Runs one static-route write; removals go through the route-wipe guard.
///
/// # Errors
///
/// Returns an `McpFailure` naming the refusal or failure to report to the client.
// NOT cancel-safe: transmitted work may precede verification or recovery cleanup.
pub(super) async fn routing(server: &KccMcp, arguments: Value) -> Result<Value, McpFailure> {
    let input: RouteInput = parse(arguments)?;
    check_op(ROUTING_OPS, &input.op)?;
    let opened = open(
        server,
        Area::Routing,
        (input.host.clone(), &input.op, input.confirm),
    )
    .await?;
    let ctx = &opened.2;
    let destination = text(Some(&input.destination))?;
    let interface = input
        .interface
        .as_deref()
        .map(|value| text(Some(value)))
        .transpose()?;
    if input.op == "ipv4_route" {
        let mut route = Ipv4Route::network(destination, text(input.mask.as_deref())?, "");
        route.gateway = input
            .gateway
            .as_deref()
            .map(|value| text(Some(value)))
            .transpose()?
            .map(str::to_owned);
        route.interface = interface.map(str::to_owned);
        route.metric = input.metric;
        if input.remove {
            let operation = route_change::plan_remove_ipv4(ctx, &route).map_err(map_domain)?;
            let result = apply(
                server,
                &opened,
                (&operation, input.confirm, async |changes| {
                    route_change::remove_ipv4(changes, ctx, &route)
                        .await
                        .map_err(map_domain)
                }),
            )
            .await?;
            return Ok(applied(result.unsaved, &result.audit));
        }
        let planned = route_change::plan_add_ipv4(ctx, &route);
        return apply_cli(
            server,
            &opened,
            (planned, input.confirm, route_change::request),
        )
        .await;
    }
    let mut route = Ipv6Route::via_gateway(destination, "");
    route.gateway = input
        .gateway
        .as_deref()
        .map(|value| text(Some(value)))
        .transpose()?
        .map(str::to_owned);
    route.interface = interface.map(str::to_owned);
    if input.remove {
        let operation = route_change::plan_remove_ipv6(ctx, &route).map_err(map_domain)?;
        let result = apply(
            server,
            &opened,
            (&operation, input.confirm, async |changes| {
                route_change::remove_ipv6(changes, ctx, &route)
                    .await
                    .map_err(map_domain)
            }),
        )
        .await?;
        return Ok(applied(result.unsaved, &result.audit));
    }
    let planned = route_change::plan_add_ipv6(ctx, &route);
    apply_cli(
        server,
        &opened,
        (planned, input.confirm, route_change::request),
    )
    .await
}

/// Plans one policy change.
///
/// # Errors
///
/// Returns an `McpFailure` naming the refusal or failure to report to the client.
fn plan_policy(
    ctx: &RouterCtx,
    input: &PolicyInput,
) -> Result<Result<ChangeOp, DomainError>, McpFailure> {
    let name = text(Some(&input.name))?;
    let interface = || text(input.interface.as_deref());
    let rate = |direction| -> Result<PolicyRateLimit, McpFailure> {
        Ok(match input.number {
            Some(rate) => PolicyRateLimit::fixed(interface()?, direction, rate),
            None => PolicyRateLimit::automatic(interface()?, direction),
        })
    };
    Ok(match input.op.as_str() {
        "policy" if input.enabled => policy::create(ctx, name),
        "policy" => policy::remove(ctx, name),
        "description" => policy::description(ctx, name, input.description.as_deref()),
        "permit" => {
            let mut permit = PolicyPermit::new(interface()?);
            permit.order = input.number;
            policy::permit(ctx, name, &permit, input.enabled)
        }
        "multipath" => policy::multipath(ctx, name, input.enabled),
        "route" => {
            let destination = text(input.destination.as_deref())?;
            let route = match input.mask.as_deref() {
                Some(mask) => PolicyRoute::network(destination, text(Some(mask))?, interface()?),
                None => PolicyRoute::host(destination, text(input.gateway.as_deref())?),
            };
            policy::route(ctx, name, &route, input.enabled)
        }
        "rate_limit_input" => {
            policy::rate_limit(ctx, name, &rate(RateDirection::Input)?, input.enabled)
        }
        "rate_limit_output" => {
            policy::rate_limit(ctx, name, &rate(RateDirection::Output)?, input.enabled)
        }
        _ => policy::standalone(ctx, name, input.enabled),
    })
}

/// Runs one policy write.
///
/// # Errors
///
/// Returns an `McpFailure` naming the refusal or failure to report to the client.
// NOT cancel-safe: transmitted work may precede verification or recovery cleanup.
pub(super) async fn policies(server: &KccMcp, arguments: Value) -> Result<Value, McpFailure> {
    let input: PolicyInput = parse(arguments)?;
    check_op(POLICY_OPS, &input.op)?;
    let opened = open(
        server,
        Area::Policies,
        (input.host.clone(), &input.op, input.confirm),
    )
    .await?;
    let operation = plan_policy(&opened.2, &input)?.map_err(map_domain)?;
    let result = apply(
        server,
        &opened,
        (&operation, input.confirm, async |changes| {
            apply_policy(changes, &opened.2, &operation)
                .await
                .map_err(map_domain)
        }),
    )
    .await?;
    Ok(applied(result.unsaved, &result.audit))
}
