//! Firewall and schedule writes.

use kcc_app::permissions::Permission;
use kcc_domain::{
    DomainError,
    firewall::{
        change::{self as firewall_change, RuleProperty},
        model::{Action, Direction, Protocol, Rule},
        read as firewall_read,
        rule_list::ListedRule,
    },
    schedules::{self, ActionTime, ScheduleAction},
};

use super::{
    args_dom_admin::{
        AclDirection, ActionChoice, FirewallWriteCommand, RuleProtocolChoice,
        SchedulesWriteCommand, VerdictChoice,
    },
    args_dom_family::Family,
    args_domains_net::{FirewallCommand, SchedulesCommand},
    change::{Gate, applied},
    context::Ctx,
    dom_net,
    domains::Session,
    exit::Outcome,
};

/// Runs a `firewall` command: the first commands, or the writes added here.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: changes may apply before cancellation.
pub(crate) async fn firewall(
    ctx: &Ctx,
    command: Family<FirewallCommand, FirewallWriteCommand>,
) -> Outcome {
    match command {
        Family::Base(sub) => dom_net::firewall(ctx, sub).await,
        Family::Writes(sub) => firewall_writes(ctx, sub).await,
    }
}

/// Runs a firewall write.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: changes may apply before cancellation.
async fn firewall_writes(ctx: &Ctx, command: FirewallWriteCommand) -> Outcome {
    let session = Session::open(ctx, Permission::Write).await?;
    let router = session.router();
    let operation = match command {
        FirewallWriteCommand::Rule {
            acl,
            action,
            protocol,
            source,
            source_mask,
            destination,
            destination_mask,
            source_port,
            port,
            remove,
        } => {
            let verdict = match action {
                VerdictChoice::Permit => Action::Permit,
                VerdictChoice::Deny => Action::Deny,
            };
            let mut rule = Rule::new(verdict, rule_protocol(protocol), &source, &destination);
            if let Some(mask) = source_mask {
                rule.source_mask = mask;
            }
            if let Some(mask) = destination_mask {
                rule.destination_mask = mask;
            }
            rule.source_port = source_port;
            rule.destination_port = port;
            if remove {
                firewall_change::plan_remove_rule(router, &acl, &rule)?
            } else {
                firewall_change::plan_add_rule(router, &acl, &rule)?
            }
        }
        FirewallWriteCommand::RuleProperty {
            acl,
            index,
            description,
            disable,
            schedule,
        } => {
            let position =
                usize::try_from(index).map_err(|_error| DomainError::FirewallRuleAbsent)?;
            let rules = firewall_read::configured_list(router, &acl).await?;
            let rule = rules
                .get(position)
                .and_then(ListedRule::structured)
                .ok_or(DomainError::FirewallRuleAbsent)?;
            let property = match (description.as_deref(), schedule.as_deref()) {
                (Some(text), _) => RuleProperty::Description(Some(text)),
                (None, Some(name)) => RuleProperty::Schedule(Some(name)),
                (None, None) => RuleProperty::Disable(disable),
            };
            firewall_change::plan_rule_property(router, &acl, rule, property)?
        }
        FirewallWriteCommand::Bind {
            acl,
            interface,
            direction,
            remove,
        } => {
            let bound = match direction {
                AclDirection::In => Direction::In,
                AclDirection::Out => Direction::Out,
            };
            firewall_change::plan_bind(router, &interface, &acl, bound, !remove)?
        }
    }
    .classify(router)
    .await;
    session
        .change(Gate::of(operation.operation()), async |changes, context| {
            Ok(applied(
                firewall_change::apply(changes, context, &operation)
                    .await?
                    .unsaved,
            ))
        })
        .await
}

/// The access-list protocol of the command line.
const fn rule_protocol(choice: RuleProtocolChoice) -> Protocol {
    match choice {
        RuleProtocolChoice::Ip => Protocol::Ip,
        RuleProtocolChoice::Tcp => Protocol::Tcp,
        RuleProtocolChoice::Udp => Protocol::Udp,
        RuleProtocolChoice::Icmp => Protocol::Icmp,
        RuleProtocolChoice::Esp => Protocol::Esp,
        RuleProtocolChoice::Gre => Protocol::Gre,
        RuleProtocolChoice::Ipip => Protocol::IpIp,
    }
}

/// Runs a `schedules` command: the first commands, or the writes added here.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: changes may apply before cancellation.
pub(crate) async fn schedules(
    ctx: &Ctx,
    command: Family<SchedulesCommand, SchedulesWriteCommand>,
) -> Outcome {
    match command {
        Family::Base(sub) => dom_net::schedules(ctx, sub).await,
        Family::Writes(sub) => schedules_writes(ctx, sub).await,
    }
}

/// Runs a schedule action write.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: changes may apply before cancellation.
async fn schedules_writes(ctx: &Ctx, command: SchedulesWriteCommand) -> Outcome {
    let SchedulesWriteCommand::Action {
        name,
        action,
        minute,
        hour,
        days,
    } = command;
    let session = Session::open(ctx, Permission::Write).await?;
    let kind = match action {
        ActionChoice::Start => ScheduleAction::Start,
        ActionChoice::Stop => ScheduleAction::Stop,
    };
    let time = ActionTime::new(kind, minute, hour, days);
    let operation = schedules::plan_action(session.router(), &name, time)?;
    session
        .cli(&operation, schedules::change_request(&operation)?)
        .await
}
