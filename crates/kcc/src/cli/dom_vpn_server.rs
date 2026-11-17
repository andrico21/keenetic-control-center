//! VPN server writes: typed `VpnServerChange`s and secret-safe keys and passwords.

use kcc_app::permissions::Permission;
use kcc_domain::{
    vpn_clients,
    vpn_servers::{self, VpnServerChange, VpnServerService, secrets as server_secrets},
};

use super::{
    args_dom_family::Family,
    args_dom_vpn_server::{PoolServer, ServiceKind, VpnServerSecretCommand, VpnServerWriteCommand},
    args_domains_wire::VpnServerCommand,
    context::Ctx,
    dom_net::new_secret,
    dom_wire::{self, object},
    domains::Session,
    exit::Outcome,
};

/// Runs a `vpn-server` command: reads, configuration changes, or key material.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: changes may apply before cancellation.
pub(crate) async fn vpn_server(
    ctx: &Ctx,
    command: Family<VpnServerCommand, Family<VpnServerWriteCommand, VpnServerSecretCommand>>,
) -> Outcome {
    match command {
        Family::Base(sub) => dom_wire::vpn_server(ctx, sub).await,
        Family::Writes(Family::Base(sub)) => {
            let session = Session::open(ctx, Permission::Write).await?;
            let operation = vpn_servers::plan_change(session.router(), &change(sub))?;
            session
                .cli(&operation, vpn_servers::change_request(&operation)?)
                .await
        }
        Family::Writes(Family::Writes(sub)) => secrets(ctx, sub).await,
    }
}

/// Runs an IKE key or VPN user password write.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: changes may apply before cancellation.
async fn secrets(ctx: &Ctx, command: VpnServerSecretCommand) -> Outcome {
    match command {
        VpnServerSecretCommand::IkePsk { name } => {
            let session = Session::open(ctx, Permission::Write).await?;
            let key_name = object(&name)?;
            let psk = new_secret(ctx, &name)?;
            let operation = server_secrets::plan_ike_psk(session.router(), key_name, psk)?;
            session
                .cli(&operation, vpn_clients::change_request(&operation)?)
                .await
        }
        VpnServerSecretCommand::Password { user } => {
            let session = Session::open_for_account(ctx, Permission::ManageUsers, &user).await?;
            let account = object(&user)?;
            let password = new_secret(ctx, &user)?;
            let operation = server_secrets::plan_password(
                session.router(),
                &account,
                &session.profile_login()?,
                password,
            )?;
            session
                .cli(&operation, server_secrets::password_request(&operation)?)
                .await
        }
    }
}

/// The typed VPN server change of the command line.
fn change(command: VpnServerWriteCommand) -> VpnServerChange {
    match command {
        VpnServerWriteCommand::Service { service, state } => VpnServerChange::Service {
            service: match service {
                ServiceKind::Vpn => VpnServerService::Vpn,
                ServiceKind::Sstp => VpnServerService::Sstp,
                ServiceKind::Ipsec => VpnServerService::Ipsec,
                ServiceKind::Openconnect => VpnServerService::OpenConnect,
            },
            enabled: state.enabled(),
        },
        VpnServerWriteCommand::Interface { server, interface } => match server {
            PoolServer::Vpn => VpnServerChange::VpnInterface { interface },
            PoolServer::Sstp => VpnServerChange::SstpInterface { interface },
            PoolServer::Openconnect => VpnServerChange::OpenConnectInterface { interface },
        },
        VpnServerWriteCommand::Pool {
            server,
            begin,
            size,
        } => match server {
            PoolServer::Vpn => VpnServerChange::VpnPool { begin, size },
            PoolServer::Sstp => VpnServerChange::SstpPool { begin, size },
            PoolServer::Openconnect => VpnServerChange::OpenConnectPool { begin, size },
        },
        VpnServerWriteCommand::WireguardInterface { interface, state } => {
            VpnServerChange::WireGuardInterface {
                interface,
                enabled: state.enabled(),
            }
        }
        VpnServerWriteCommand::IpsecVirtualIp { map, state } => VpnServerChange::IpsecVirtualIp {
            name: map,
            enabled: state.enabled(),
        },
    }
}
