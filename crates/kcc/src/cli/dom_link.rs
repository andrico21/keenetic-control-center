//! Interface, internet connection and mesh commands.

use kcc_app::permissions::Permission;
use kcc_catalog::Risk;
use kcc_domain::{
    interfaces::{self, SecurityLevel},
    mesh::{self, RebootError},
    wan::{self, StaticAddress},
};
use kcc_i18n::keys;
use serde_json::json;

use super::{
    args_dom_admin::LevelChoice,
    args_dom_link::{InterfacesCommand, MeshCommand, WanCommand},
    change::{Gate, applied},
    context::Ctx,
    dom_net::new_secret,
    dom_wire::object,
    domains::Session,
    exit::{Exit, Failure, Outcome},
};

/// Runs an `interfaces` command.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: changes may apply before cancellation.
pub(crate) async fn interfaces(ctx: &Ctx, command: InterfacesCommand) -> Outcome {
    let permission = match command {
        InterfacesCommand::List
        | InterfacesCommand::Show { name: _ }
        | InterfacesCommand::Stats => Permission::Read,
        InterfacesCommand::Up { name: _ }
        | InterfacesCommand::Down { name: _ }
        | InterfacesCommand::Description { name: _, text: _ }
        | InterfacesCommand::SecurityLevel { name: _, level: _ } => Permission::Write,
    };
    let session = Session::open(ctx, permission).await?;
    let router = session.router();
    let (name, operation) = match command {
        InterfacesCommand::List => {
            return session.show(&interfaces::read_interfaces(router).await?);
        }
        InterfacesCommand::Stats => {
            return session.show(&interfaces::read_statistics(router).await?);
        }
        InterfacesCommand::Show { name } => {
            return session.show(&interfaces::read_interface(router, &object(&name)?).await?);
        }
        InterfacesCommand::Up { name } => {
            let object_name = object(&name)?;
            let operation = interfaces::plan_up(router, &object_name)?;
            (object_name, operation)
        }
        InterfacesCommand::Down { name } => {
            let object_name = object(&name)?;
            let verdict = interfaces::detect_management(router, &object_name).await?;
            let operation = interfaces::plan_down(router, &object_name, verdict)?;
            (object_name, operation)
        }
        InterfacesCommand::Description { name, text } => {
            let object_name = object(&name)?;
            let operation = interfaces::plan_description(router, &object_name, &text)?;
            (object_name, operation)
        }
        InterfacesCommand::SecurityLevel { name, level } => {
            let object_name = object(&name)?;
            let zone = match level {
                LevelChoice::Public => SecurityLevel::Public,
                LevelChoice::Private => SecurityLevel::Private,
                LevelChoice::Protected => SecurityLevel::Protected,
            };
            let verdict = interfaces::detect_management(router, &object_name).await?;
            let operation = interfaces::plan_security_level(router, &object_name, zone, verdict)?;
            (object_name, operation)
        }
    };
    session
        .change(Gate::of(&operation), async |changes, _context| {
            let result = interfaces::apply(changes, &name, &operation)
                .await
                .map_err(Failure::from)?;
            Ok(applied(result.unsaved))
        })
        .await
}

/// Runs a `wan` command.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: changes may apply before cancellation.
pub(crate) async fn wan(ctx: &Ctx, command: WanCommand) -> Outcome {
    let permission = match command {
        WanCommand::List => Permission::Read,
        WanCommand::Identity {
            name: _,
            identity: _,
        }
        | WanCommand::Password { name: _ }
        | WanCommand::Priority { name: _, value: _ }
        | WanCommand::Mtu { name: _, value: _ }
        | WanCommand::DefaultRoute { name: _, state: _ }
        | WanCommand::Create { name: _ }
        | WanCommand::Delete { name: _ }
        | WanCommand::Static {
            name: _,
            address: _,
            mask: _,
        }
        | WanCommand::Dhcp { name: _ }
        | WanCommand::ConnectVia { name: _, via: _ } => Permission::Write,
    };
    let session = Session::open(ctx, permission).await?;
    let router = session.router();
    let (name, operation) = match command {
        WanCommand::List => return session.show(&wan::read_connections(router).await?),
        WanCommand::Identity { name, identity } => {
            let object_name = object(&name)?;
            let operation = wan::plan_identity(router, &object_name, &identity).await?;
            (object_name, operation)
        }
        WanCommand::Password { name } => {
            let object_name = object(&name)?;
            let operation =
                wan::plan_password(router, &object_name, new_secret(ctx, &name)?).await?;
            (object_name, operation)
        }
        WanCommand::Priority { name, value } => {
            let object_name = object(&name)?;
            let operation = wan::plan_priority(router, &object_name, value).await?;
            (object_name, operation)
        }
        WanCommand::Mtu { name, value } => {
            let object_name = object(&name)?;
            let operation = wan::plan_mtu(router, &object_name, value).await?;
            (object_name, operation)
        }
        WanCommand::DefaultRoute { name, state } => {
            let object_name = object(&name)?;
            let operation = wan::plan_default_route(router, &object_name, state.enabled()).await?;
            (object_name, operation)
        }
        WanCommand::Create { name } => {
            let object_name = object(&name)?;
            let operation = wan::plan_create(router, &object_name).await?;
            (object_name, operation)
        }
        WanCommand::Delete { name } => {
            let object_name = object(&name)?;
            let operation = wan::plan_delete(router, &object_name).await?;
            (object_name, operation)
        }
        WanCommand::Static {
            name,
            address,
            mask,
        } => {
            let object_name = object(&name)?;
            let verdict = interfaces::detect_management(router, &object_name).await?;
            let addressing = StaticAddress::new(address, mask);
            let operation = wan::plan_static_address(router, &object_name, addressing, verdict)?;
            (object_name, operation)
        }
        WanCommand::Dhcp { name } => {
            let object_name = object(&name)?;
            let verdict = interfaces::detect_management(router, &object_name).await?;
            let operation = wan::plan_dhcp(router, &object_name, verdict)?;
            (object_name, operation)
        }
        WanCommand::ConnectVia { name, via } => {
            let object_name = object(&name)?;
            let operation = wan::plan_connect_via(router, &object_name, &object(&via)?).await?;
            (object_name, operation)
        }
    };
    session
        .cli(&operation, wan::change_request(&name, &operation)?)
        .await
}

/// Runs a `mesh` command; a member reboot needs the member id typed twice.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: changes may apply before cancellation.
pub(crate) async fn mesh(ctx: &Ctx, command: MeshCommand) -> Outcome {
    if let MeshCommand::Reboot {
        member,
        confirm_member,
    } = &command
        && confirm_member != member
    {
        return Err(Failure::message(
            Exit::Policy,
            keys::CLI_CONFIRM_MISSING,
            &[("router", member)],
        ));
    }
    let permission = match command {
        MeshCommand::Members | MeshCommand::Associations => Permission::Read,
        MeshCommand::UpdateCheck { member: _ }
        | MeshCommand::UpdateStart { member: _ }
        | MeshCommand::Acquire { candidate: _ } => Permission::Write,
        MeshCommand::Reboot {
            member: _,
            confirm_member: _,
        } => Permission::Destructive,
    };
    let session = Session::open(ctx, permission).await?;
    let router = session.router();
    let operation = match command {
        MeshCommand::Members => return session.show(&mesh::read_members(router).await?),
        MeshCommand::Associations => return session.show(&mesh::read_associations(router).await?),
        MeshCommand::UpdateCheck { member } => mesh::plan_update_check(router, &member)?,
        MeshCommand::UpdateStart { member } => mesh::plan_update_start(router, &member)?,
        MeshCommand::Acquire { candidate } => mesh::plan_acquire(router, &candidate)?,
        MeshCommand::Reboot {
            member,
            confirm_member,
        } => {
            let gate = Gate::new(Risk::Destructive, Permission::Destructive, false);
            return session
                .change(gate, async |changes, context| {
                    drop(
                        mesh::reboot_member(changes, context, &member, &confirm_member)
                            .await
                            .map_err(reboot_failure)?,
                    );
                    Ok(json!({ "applied": true, "rebooting": member }))
                })
                .await;
        }
    };
    session
        .cli(&operation, mesh::change_request(&operation)?)
        .await
}

/// Maps a mesh reboot failure.
fn reboot_failure(error: RebootError) -> Failure {
    match error {
        RebootError::Domain(domain) => Failure::from(domain),
        RebootError::Workflow(workflow) => Failure::from(workflow),
        RebootError::ConfirmationMismatch | _ => Failure::text(Exit::Policy, &error),
    }
}
