//! Connection-policy writes.

use kcc_app::permissions::Permission;
use kcc_domain::policies::{
    change::{apply::apply as apply_policy, plan as policy},
    model::{PolicyPermit, PolicyRateLimit, PolicyRoute, RateDirection},
};

use super::{
    args_dom_family::Family,
    args_dom_lan::{DirectionChoice, PoliciesWriteCommand},
    args_domains_net::PoliciesCommand,
    change::{Gate, applied},
    context::Ctx,
    dom_net,
    domains::Session,
    exit::Outcome,
};

/// Runs a `policies` command: the first commands, or the writes added here.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: changes may apply before cancellation.
pub(crate) async fn policies(
    ctx: &Ctx,
    command: Family<PoliciesCommand, PoliciesWriteCommand>,
) -> Outcome {
    match command {
        Family::Base(sub) => dom_net::policies(ctx, sub).await,
        Family::Writes(sub) => policies_writes(ctx, sub).await,
    }
}

/// Runs a connection-policy write.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: changes may apply before cancellation.
async fn policies_writes(ctx: &Ctx, command: PoliciesWriteCommand) -> Outcome {
    let session = Session::open(ctx, Permission::Write).await?;
    let router = session.router();
    let operation = match command {
        PoliciesWriteCommand::Create { name } => policy::create(router, &name)?,
        PoliciesWriteCommand::Delete { name } => policy::remove(router, &name)?,
        PoliciesWriteCommand::Description { name, text } => {
            policy::description(router, &name, text.as_deref())?
        }
        PoliciesWriteCommand::Permit {
            name,
            interface,
            order,
            remove,
        } => {
            let mut permit = PolicyPermit::new(&interface);
            permit.order = order;
            policy::permit(router, &name, &permit, !remove)?
        }
        PoliciesWriteCommand::Multipath { name, state } => {
            policy::multipath(router, &name, state.enabled())?
        }
        PoliciesWriteCommand::Route {
            name,
            destination,
            mask,
            interface,
            gateway,
            metric,
            remove,
        } => {
            let mut route = mask.map_or_else(
                || PolicyRoute::host(&destination, gateway.as_deref().unwrap_or_default()),
                |network_mask| {
                    PolicyRoute::network(
                        &destination,
                        &network_mask,
                        interface.as_deref().unwrap_or_default(),
                    )
                },
            );
            route.metric = metric;
            policy::route(router, &name, &route, !remove)?
        }
        PoliciesWriteCommand::RateLimit {
            name,
            interface,
            direction,
            rate,
            remove,
        } => {
            let way = match direction {
                DirectionChoice::Input => RateDirection::Input,
                DirectionChoice::Output => RateDirection::Output,
            };
            let limit = rate.map_or_else(
                || PolicyRateLimit::automatic(&interface, way),
                |value| PolicyRateLimit::fixed(&interface, way, value),
            );
            policy::rate_limit(router, &name, &limit, !remove)?
        }
        PoliciesWriteCommand::Standalone { name, state } => {
            policy::standalone(router, &name, state.enabled())?
        }
    };
    session
        .change(Gate::of(&operation), async |changes, context| {
            Ok(applied(
                apply_policy(changes, context, &operation).await?.unsaved,
            ))
        })
        .await
}
