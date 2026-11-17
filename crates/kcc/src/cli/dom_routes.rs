//! Route and NAT commands.

use kcc_app::permissions::Permission;
use kcc_domain::{
    nat::{
        self,
        model::{PortForward, Protocol},
    },
    routing::{
        self,
        model::{Ipv4Route, Ipv6Route},
    },
};
use kcc_i18n::keys;
use serde_json::json;

use super::{
    args_domains_net::{ForwardArgs, ForwardProtocol, NatCommand, RouteArgs, RoutesCommand},
    change::{Gate, applied},
    context::Ctx,
    domains::Session,
    exit::{Exit, Failure, Outcome},
};

/// Runs a `routes` command.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: changes may apply before cancellation.
pub(crate) async fn routes(ctx: &Ctx, command: RoutesCommand) -> Outcome {
    let permission = if matches!(command, RoutesCommand::List { ipv6: _ }) {
        Permission::Read
    } else {
        Permission::Write
    };
    let session = Session::open(ctx, permission).await?;
    let router = session.router();
    match command {
        RoutesCommand::List { ipv6: false } => {
            session.show(&routing::read::ipv4_table(router).await?)
        }
        RoutesCommand::List { ipv6: true } => {
            session.show(&routing::read::ipv6_table(router).await?)
        }
        RoutesCommand::Add(route) if route.ipv6 => {
            let operation = routing::change::plan_add_ipv6(router, &ipv6(&route)?)?;
            session
                .cli(&operation, routing::change::request(&operation)?)
                .await
        }
        RoutesCommand::Add(route) => {
            let operation = routing::change::plan_add_ipv4(router, &ipv4(&route))?;
            session
                .cli(&operation, routing::change::request(&operation)?)
                .await
        }
        RoutesCommand::Remove(route) if route.ipv6 => {
            let target = ipv6(&route)?;
            let operation = routing::change::plan_remove_ipv6(router, &target)?;
            session
                .change(Gate::of(&operation), async |changes, context| {
                    let result = routing::change::remove_ipv6(changes, context, &target).await?;
                    Ok(applied(result.unsaved))
                })
                .await
        }
        RoutesCommand::Remove(route) => {
            let target = ipv4(&route);
            let operation = routing::change::plan_remove_ipv4(router, &target)?;
            session
                .change(Gate::of(&operation), async |changes, context| {
                    let result = routing::change::remove_ipv4(changes, context, &target).await?;
                    Ok(applied(result.unsaved))
                })
                .await
        }
    }
}

/// The IPv4 route of the command line.
fn ipv4(args: &RouteArgs) -> Ipv4Route {
    let mut route = Ipv4Route::network(
        &args.destination,
        args.mask.as_deref().unwrap_or_default(),
        args.gateway.as_deref().unwrap_or_default(),
    );
    route.mask.clone_from(&args.mask);
    route.gateway.clone_from(&args.gateway);
    route.interface.clone_from(&args.interface);
    route.metric = args.metric;
    route
}

/// The IPv6 route of the command line.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
fn ipv6(args: &RouteArgs) -> Outcome<Ipv6Route> {
    if args.mask.is_some() || args.metric.is_some() {
        return Err(Failure::message(
            Exit::Usage,
            keys::CLI_ROUTE_IPV4_OPTIONS,
            &[],
        ));
    }
    let mut route = Ipv6Route::via_gateway(
        &args.destination,
        args.gateway.as_deref().unwrap_or_default(),
    );
    route.gateway.clone_from(&args.gateway);
    route.interface.clone_from(&args.interface);
    Ok(route)
}

/// Runs a `nat` command.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: changes may apply before cancellation.
pub(crate) async fn nat(ctx: &Ctx, command: NatCommand) -> Outcome {
    let permission = match command {
        NatCommand::Forwards
        | NatCommand::StartupForwards
        | NatCommand::Interfaces
        | NatCommand::Sessions { offset: _ } => Permission::Read,
        NatCommand::AddForward(_)
        | NatCommand::RemoveForward(_)
        | NatCommand::AddInterface { name: _ }
        | NatCommand::RemoveInterface { name: _ } => Permission::Write,
    };
    let session = Session::open(ctx, permission).await?;
    let router = session.router();
    let operation = match command {
        NatCommand::Forwards => return session.show(&nat::read::running_forwards(router).await?),
        NatCommand::StartupForwards => {
            return session.show(&nat::read::startup_forwards(router).await?);
        }
        NatCommand::Interfaces => return session.show(&nat::read::interfaces(router).await?),
        NatCommand::Sessions { offset } => {
            let page = nat::read::sessions_page(router, offset).await?;
            let rows = page.rows.iter().map(|row| &row.fields).collect::<Vec<_>>();
            return session.show(&json!({ "offset": page.offset, "rows": rows }));
        }
        NatCommand::AddForward(rule) => nat::change::plan_add_forward(router, &forward(&rule))?,
        NatCommand::RemoveForward(rule) => {
            nat::change::plan_remove_forward(router, &forward(&rule))?
        }
        NatCommand::AddInterface { name } => nat::change::plan_add_interface(router, &name)?,
        NatCommand::RemoveInterface { name } => nat::change::plan_remove_interface(router, &name)?,
    };
    session
        .change(Gate::of(&operation), async |changes, context| {
            Ok(applied(
                nat::change::apply(changes, context, &operation)
                    .await?
                    .unsaved,
            ))
        })
        .await
}

/// The port forward of the command line.
fn forward(args: &ForwardArgs) -> PortForward {
    let protocol = match args.protocol {
        ForwardProtocol::Tcp => Protocol::Tcp,
        ForwardProtocol::Udp => Protocol::Udp,
    };
    let rule = PortForward::to_address(protocol, &args.interface, args.port, &args.to_address);
    match args.to_port {
        Some(port) => rule.with_to_port(port),
        None => rule,
    }
}
