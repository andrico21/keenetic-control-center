//! Interface security-level, internet connection, Wi-Fi and mesh writes.

use kcc_app::permissions::Permission;
use kcc_catalog::Risk;
use kcc_domain::{
    interfaces::{self, SecurityLevel},
    mesh::{self, RebootError},
    wan::{self, StaticAddress},
    wifi::{self, Encryption},
};
use kcc_i18n::keys;
use serde_json::json;

use super::{
    args_dom_admin::LevelChoice,
    args_dom_family::Family,
    args_dom_link::{
        EncryptionChoice, InterfacesWriteCommand, MeshWriteCommand, WanWriteCommand,
        WifiWriteCommand,
    },
    args_domains_wire::{InterfacesCommand, MeshCommand, WanCommand, WifiCommand},
    change::{Gate, applied},
    context::Ctx,
    dom_wifi,
    dom_wire::{self, object},
    domains::Session,
    exit::{Exit, Failure, Outcome},
};

/// Runs an `interfaces` command.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: changes may apply before cancellation.
pub(crate) async fn interfaces(
    ctx: &Ctx,
    command: Family<InterfacesCommand, InterfacesWriteCommand>,
) -> Outcome {
    let InterfacesWriteCommand::SecurityLevel { name, level } = match command {
        Family::Base(sub) => return dom_wire::interfaces(ctx, sub).await,
        Family::Writes(sub) => sub,
    };
    let session = Session::open(ctx, Permission::Write).await?;
    let router = session.router();
    let object_name = object(&name)?;
    let zone = match level {
        LevelChoice::Public => SecurityLevel::Public,
        LevelChoice::Private => SecurityLevel::Private,
        LevelChoice::Protected => SecurityLevel::Protected,
    };
    let verdict = interfaces::detect_management(router, &object_name).await?;
    let operation = interfaces::plan_security_level(router, &object_name, zone, verdict)?;
    let gate = Gate::of(&operation).self_bracketed();
    session
        .change(gate, async |changes, context| {
            let result = interfaces::apply(changes, context, &object_name, operation, true)
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
pub(crate) async fn wan(ctx: &Ctx, command: Family<WanCommand, WanWriteCommand>) -> Outcome {
    let sub = match command {
        Family::Base(sub) => return dom_wire::wan(ctx, sub).await,
        Family::Writes(sub) => sub,
    };
    let session = Session::open(ctx, Permission::Write).await?;
    let router = session.router();
    let (name, operation) = match sub {
        WanWriteCommand::Create { name } => {
            let object_name = object(&name)?;
            let operation = wan::plan_create(router, &object_name).await?;
            (object_name, operation)
        }
        WanWriteCommand::Delete { name } => {
            let object_name = object(&name)?;
            let operation = wan::plan_delete(router, &object_name).await?;
            (object_name, operation)
        }
        WanWriteCommand::Static {
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
        WanWriteCommand::Dhcp { name } => {
            let object_name = object(&name)?;
            let verdict = interfaces::detect_management(router, &object_name).await?;
            let operation = wan::plan_dhcp(router, &object_name, verdict)?;
            (object_name, operation)
        }
        WanWriteCommand::ConnectVia { name, via } => {
            let object_name = object(&name)?;
            let operation = wan::plan_connect_via(router, &object_name, &object(&via)?)?;
            (object_name, operation)
        }
    };
    session
        .cli(&operation, wan::change_request(&name, &operation)?)
        .await
}

/// Runs a `wifi` command.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: changes may apply before cancellation.
pub(crate) async fn wifi(ctx: &Ctx, command: Family<WifiCommand, WifiWriteCommand>) -> Outcome {
    let sub = match command {
        Family::Base(sub) => return dom_wifi::wifi(ctx, sub).await,
        Family::Writes(sub) => sub,
    };
    let session = Session::open(ctx, Permission::Write).await?;
    let router = session.router();
    let (name, operation) = match sub {
        WifiWriteCommand::Encryption { ap, mode } => {
            let name = object(&ap)?;
            let encryption = match mode {
                EncryptionChoice::Enable => Encryption::Enable,
                EncryptionChoice::Wpa2 => Encryption::Wpa2,
                EncryptionChoice::Wpa3 => Encryption::Wpa3,
            };
            let operation = wifi::plan_encryption(router, &name, encryption)?;
            (name, operation)
        }
        WifiWriteCommand::Schedule { ap, schedule } => {
            let name = object(&ap)?;
            let operation = wifi::plan_schedule(router, &name, &schedule).await?;
            (name, operation)
        }
        WifiWriteCommand::ChannelWidth { ap, width } => {
            let name = object(&ap)?;
            let operation = wifi::plan_channel_width(router, &name, &width)?;
            (name, operation)
        }
        WifiWriteCommand::BandSteering { ap, state } => {
            let name = object(&ap)?;
            let operation = wifi::plan_band_steering(router, &name, state.enabled())?;
            (name, operation)
        }
    };
    session
        .cli(&operation, wifi::change_request(&name, &operation)?)
        .await
}

/// Runs a `mesh` command; a member reboot needs the member id typed twice.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: changes may apply before cancellation.
pub(crate) async fn mesh(ctx: &Ctx, command: Family<MeshCommand, MeshWriteCommand>) -> Outcome {
    match command {
        Family::Base(sub) => dom_wire::mesh(ctx, sub).await,
        Family::Writes(MeshWriteCommand::Acquire { candidate }) => {
            let session = Session::open(ctx, Permission::Write).await?;
            let operation = mesh::plan_acquire(session.router(), &candidate)?;
            session
                .cli(&operation, mesh::change_request(&operation)?)
                .await
        }
        Family::Writes(MeshWriteCommand::Reboot {
            member,
            confirm_member,
        }) => {
            if confirm_member != member {
                return Err(Failure::message(
                    Exit::Policy,
                    keys::CLI_CONFIRM_MISSING,
                    &[("router", &member)],
                ));
            }
            let session = Session::open(ctx, Permission::Destructive).await?;
            let gate = Gate::new(Risk::Destructive, Permission::Destructive, false);
            session
                .change(gate, async |changes, router| {
                    drop(
                        mesh::reboot_member(changes, router, &member, &confirm_member)
                            .await
                            .map_err(reboot_failure)?,
                    );
                    Ok(json!({ "applied": true, "rebooting": member }))
                })
                .await
        }
    }
}

/// Maps a mesh reboot failure.
fn reboot_failure(error: RebootError) -> Failure {
    match error {
        RebootError::Domain(domain) => Failure::from(domain),
        RebootError::Workflow(workflow) => Failure::from(workflow),
        RebootError::ConfirmationMismatch | _ => Failure::text(Exit::Policy, &error),
    }
}
