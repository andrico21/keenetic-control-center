//! Firewall and schedule commands.

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
        AclDirection, ActionChoice, FirewallCommand, RuleProtocolChoice, SchedulesCommand,
        VerdictChoice,
    },
    change::{Gate, applied},
    context::Ctx,
    domains::Session,
    exit::Outcome,
};

/// Runs a `firewall` command.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: changes may apply before cancellation.
pub(crate) async fn firewall(ctx: &Ctx, command: FirewallCommand) -> Outcome {
    let session = Session::open(ctx, firewall_permission(&command)).await?;
    let router = session.router();
    let operation = match command {
        FirewallCommand::AccessLists => {
            return session.show(&firewall_read::access_lists(router).await?);
        }
        FirewallCommand::Upnp => {
            return session.show(&firewall_read::upnp_redirects(router).await?);
        }
        FirewallCommand::Rule {
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
        FirewallCommand::RuleProperty {
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
        FirewallCommand::Bind {
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

/// The permission a `firewall` command needs.
const fn firewall_permission(command: &FirewallCommand) -> Permission {
    match command {
        FirewallCommand::AccessLists | FirewallCommand::Upnp => Permission::Read,
        FirewallCommand::Rule {
            acl: _,
            action: _,
            protocol: _,
            source: _,
            source_mask: _,
            destination: _,
            destination_mask: _,
            source_port: _,
            port: _,
            remove: _,
        }
        | FirewallCommand::RuleProperty {
            acl: _,
            index: _,
            description: _,
            disable: _,
            schedule: _,
        }
        | FirewallCommand::Bind {
            acl: _,
            interface: _,
            direction: _,
            remove: _,
        } => Permission::Write,
    }
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

/// Runs a `schedules` command.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: changes may apply before cancellation.
pub(crate) async fn schedules(ctx: &Ctx, command: SchedulesCommand) -> Outcome {
    let permission = match command {
        SchedulesCommand::List => Permission::Read,
        SchedulesCommand::Create { name: _ }
        | SchedulesCommand::Describe {
            name: _,
            description: _,
        }
        | SchedulesCommand::Action {
            name: _,
            action: _,
            minute: _,
            hour: _,
            days: _,
        } => Permission::Write,
    };
    let session = Session::open(ctx, permission).await?;
    let router = session.router();
    let operation = match command {
        SchedulesCommand::List => return session.show(&schedules::read_schedules(router).await?),
        SchedulesCommand::Create { name } => schedules::plan_create(router, &name)?,
        SchedulesCommand::Describe { name, description } => {
            schedules::plan_description(router, &name, &description)?
        }
        SchedulesCommand::Action {
            name,
            action,
            minute,
            hour,
            days,
        } => {
            let kind = match action {
                ActionChoice::Start => ScheduleAction::Start,
                ActionChoice::Stop => ScheduleAction::Stop,
            };
            schedules::plan_action(router, &name, ActionTime::new(kind, minute, hour, days))?
        }
    };
    session
        .cli(&operation, schedules::change_request(&operation)?)
        .await
}
