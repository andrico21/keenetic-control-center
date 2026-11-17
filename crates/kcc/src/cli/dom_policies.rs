//! Connection-policy commands.

use kcc_app::permissions::Permission;
use kcc_domain::policies::{
    change::{apply::apply as apply_policy, plan as policy},
    model::{PolicyPermit, PolicyRateLimit, PolicyRoute, RateDirection},
    read as policy_read,
};

use super::{
    args_dom_lan::{DirectionChoice, PoliciesCommand},
    change::{Gate, applied},
    context::Ctx,
    domains::Session,
    exit::Outcome,
};

/// Runs a `policies` command.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: changes may apply before cancellation.
pub(crate) async fn policies(ctx: &Ctx, command: PoliciesCommand) -> Outcome {
    let session = Session::open(ctx, policies_permission(&command)).await?;
    let router = session.router();
    let operation = match command {
        PoliciesCommand::List => {
            return session.show(&policy_read::policies(router).await?);
        }
        PoliciesCommand::Create { name } => policy::create(router, &name)?,
        PoliciesCommand::Delete { name } => policy::remove(router, &name)?,
        PoliciesCommand::Description { name, text } => {
            policy::description(router, &name, text.as_deref())?
        }
        PoliciesCommand::Permit {
            name,
            interface,
            order,
            remove,
        } => {
            let mut permit = PolicyPermit::new(&interface);
            permit.order = order;
            policy::permit(router, &name, &permit, !remove)?
        }
        PoliciesCommand::Multipath { name, state } => {
            policy::multipath(router, &name, state.enabled())?
        }
        PoliciesCommand::Route {
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
        PoliciesCommand::RateLimit {
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
        PoliciesCommand::Standalone { name, state } => {
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

/// The permission a `policies` command needs.
const fn policies_permission(command: &PoliciesCommand) -> Permission {
    match command {
        PoliciesCommand::List => Permission::Read,
        PoliciesCommand::Create { name: _ }
        | PoliciesCommand::Delete { name: _ }
        | PoliciesCommand::Description { name: _, text: _ }
        | PoliciesCommand::Permit {
            name: _,
            interface: _,
            order: _,
            remove: _,
        }
        | PoliciesCommand::Multipath { name: _, state: _ }
        | PoliciesCommand::Route {
            name: _,
            destination: _,
            mask: _,
            interface: _,
            gateway: _,
            metric: _,
            remove: _,
        }
        | PoliciesCommand::RateLimit {
            name: _,
            interface: _,
            direction: _,
            rate: _,
            remove: _,
        }
        | PoliciesCommand::Standalone { name: _, state: _ } => Permission::Write,
    }
}
