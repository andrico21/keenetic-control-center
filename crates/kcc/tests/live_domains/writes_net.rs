//! Network-side reversible writes: a static route, a port forward and a known host.

use core::{error::Error, ops::RangeInclusive};

use kcc_domain::{
    RouterCtx, clients, interfaces,
    nat::{
        self,
        model::{PortForward, Protocol},
    },
    routing::{self, model::Ipv4Route},
};

use super::writes::{WriteResult, Writer};

/// Destination of the probe route (TEST-NET-3).
const ROUTE_NETWORK: &str = "203.0.113.0";

/// Mask of the probe route.
const ROUTE_MASK: &str = "255.255.255.0";

/// Candidate external ports of the probe forward.
const FORWARD_PORTS: RangeInclusive<u16> = 65051..=65099;

/// Locally administered MAC of the probe known host.
const HOST_MAC: &str = "02:00:00:00:51:01";

/// Name of the probe known host.
const HOST_NAME: &str = "kcc-live-51";

/// The interface that carries the default route, when one does.
///
/// # Errors
/// Returns read failures.
// cancel-safe: one read.
pub(crate) async fn default_gateway(ctx: &RouterCtx) -> Result<Option<String>, Box<dyn Error>> {
    Ok(interfaces::read_interfaces(ctx)
        .await?
        .into_iter()
        .find(|(_name, interface)| interface.defaultgw == Some(true))
        .map(|(name, _interface)| name))
}

/// An up interface with an IPv4 address that does not carry the default route.
// cancel-safe: one read.
async fn local_interface(ctx: &RouterCtx) -> Result<Option<(String, String)>, Box<dyn Error>> {
    Ok(interfaces::read_interfaces(ctx)
        .await?
        .into_iter()
        .find_map(|(name, interface)| {
            let usable = interface.defaultgw != Some(true)
                && interface.state.as_deref() == Some("up")
                && interface.kind.as_deref() == Some("Bridge");
            usable
                .then_some(interface.address)
                .flatten()
                .map(|address| (name, address))
        }))
}

/// Adds a route to 203.0.113.0/24 via a non-default interface and removes it again through
/// the guarded removal.
// NOT cancel-safe: mutates the router.
pub(crate) async fn static_route(writer: &mut Writer<'_>) -> Result<WriteResult, Box<dyn Error>> {
    let Some((interface, _address)) = local_interface(writer.ctx).await? else {
        return Ok(WriteResult::Skipped("no up non-default bridge interface"));
    };
    let mut route = Ipv4Route::network(ROUTE_NETWORK, ROUTE_MASK, "").on_interface(&interface);
    route.gateway = None;
    let present = |table: &[routing::model::RouteTableEntry]| {
        table.iter().any(|entry| {
            entry.command.first().map(String::as_str) == Some(ROUTE_NETWORK)
                && entry.command.get(1).map(String::as_str) == Some(ROUTE_MASK)
        })
    };
    if present(&routing::read::ipv4_table(writer.ctx).await?) {
        return Ok(WriteResult::Skipped(
            "a 203.0.113.0/24 route already exists",
        ));
    }
    let add = routing::change::plan_add_ipv4(writer.ctx, &route)?;
    drop(
        writer
            .changes
            .apply_cli(routing::change::request(&add)?)
            .await?,
    );
    if !present(&routing::read::ipv4_table(writer.ctx).await?) {
        return Err("static route read-back failed".into());
    }
    if writer.revert {
        drop(routing::change::remove_ipv4(writer.changes, writer.ctx, &route).await?);
        if present(&routing::read::ipv4_table(writer.ctx).await?) {
            return Err("static route removal read-back failed".into());
        }
    }
    Ok(writer.done())
}

/// Adds a TCP forward on an unused external port of the default-route interface to a
/// local-segment address, then removes exactly that rule.
// NOT cancel-safe: mutates the router.
pub(crate) async fn port_forward(writer: &mut Writer<'_>) -> Result<WriteResult, Box<dyn Error>> {
    let gateway = default_gateway(writer.ctx).await?;
    let local = local_interface(writer.ctx).await?;
    let (Some(wan), Some((_lan, address))) = (gateway, local) else {
        return Ok(WriteResult::Skipped(
            "no default-route and local interface pair",
        ));
    };
    let mut octets = address.split('.').take(3).collect::<Vec<_>>();
    octets.push("254");
    let target = octets.join(".");
    let rules = nat::read::running_forwards(writer.ctx).await?;
    let used = |port: u16| {
        let text = port.to_string();
        rules.iter().any(|rule| rule.command.contains(&text))
    };
    let Some(port) = FORWARD_PORTS.clone().find(|port| !used(*port)) else {
        return Ok(WriteResult::Skipped(
            "every probe port is already forwarded",
        ));
    };
    let rule = PortForward::to_address(Protocol::Tcp, &wan, port, &target);
    let add = nat::change::plan_add_forward(writer.ctx, &rule)?;
    drop(nat::change::apply(writer.changes, writer.ctx, &add).await?);
    if writer.revert {
        let remove = nat::change::plan_remove_forward(writer.ctx, &rule)?;
        drop(nat::change::apply(writer.changes, writer.ctx, &remove).await?);
        if nat::read::running_forwards(writer.ctx).await?.len() != rules.len() {
            return Err("port forward removal read-back failed".into());
        }
    }
    Ok(writer.done())
}

/// Registers a known host with a locally administered MAC and removes it again.
// NOT cancel-safe: mutates the router.
pub(crate) async fn known_host(writer: &mut Writer<'_>) -> Result<WriteResult, Box<dyn Error>> {
    let registered = |client: Option<clients::Client>| {
        client.is_some_and(|found| found.registered == Some(true))
    };
    if registered(clients::read_client(writer.ctx, HOST_MAC).await?) {
        return Ok(WriteResult::Skipped("the probe known host already exists"));
    }
    let add = clients::plan_register(writer.ctx, HOST_MAC, HOST_NAME)?;
    drop(clients::apply(writer.changes, writer.ctx, &add).await?);
    if !registered(clients::read_client(writer.ctx, HOST_MAC).await?) {
        return Err("known host read-back failed".into());
    }
    if writer.revert {
        let remove = clients::plan_remove(writer.ctx, HOST_MAC)?;
        drop(clients::apply(writer.changes, writer.ctx, &remove).await?);
        if registered(clients::read_client(writer.ctx, HOST_MAC).await?) {
            return Err("known host removal read-back failed".into());
        }
    }
    Ok(writer.done())
}
