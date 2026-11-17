//! VPN server commands: the status, typed `VpnServerChange`s and secret-safe keys and
//! passwords.

use kcc_app::permissions::Permission;
use kcc_domain::{
    vpn_clients,
    vpn_servers::{self, VpnServerChange, VpnServerService, secrets as server_secrets},
};

use super::{
    args_dom_vpn_server::{PoolServer, ServiceKind, VpnServerCommand},
    context::Ctx,
    dom_net::new_secret,
    dom_wire::object,
    domains::Session,
    exit::Outcome,
};

/// Runs a `vpn-server` command: the status, configuration changes, or key material.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: changes may apply before cancellation.
pub(crate) async fn vpn_server(ctx: &Ctx, command: VpnServerCommand) -> Outcome {
    let change = match command {
        VpnServerCommand::Status => {
            let session = Session::open(ctx, Permission::Read).await?;
            return session.show(&vpn_servers::read_servers(session.router()).await?);
        }
        VpnServerCommand::IkePsk { name } => return ike_psk(ctx, &name).await,
        VpnServerCommand::Password { user } => return password(ctx, &user).await,
        VpnServerCommand::Service { service, state } => VpnServerChange::Service {
            service: match service {
                ServiceKind::Vpn => VpnServerService::Vpn,
                ServiceKind::Sstp => VpnServerService::Sstp,
                ServiceKind::Ipsec => VpnServerService::Ipsec,
                ServiceKind::Openconnect => VpnServerService::OpenConnect,
            },
            enabled: state.enabled(),
        },
        VpnServerCommand::Interface { server, interface } => match server {
            PoolServer::Vpn => VpnServerChange::VpnInterface { interface },
            PoolServer::Sstp => VpnServerChange::SstpInterface { interface },
            PoolServer::Openconnect => VpnServerChange::OpenConnectInterface { interface },
        },
        VpnServerCommand::Pool {
            server,
            begin,
            size,
        } => match server {
            PoolServer::Vpn => VpnServerChange::VpnPool { begin, size },
            PoolServer::Sstp => VpnServerChange::SstpPool { begin, size },
            PoolServer::Openconnect => VpnServerChange::OpenConnectPool { begin, size },
        },
        VpnServerCommand::WireguardInterface { interface, state } => {
            VpnServerChange::WireGuardInterface {
                interface,
                enabled: state.enabled(),
            }
        }
        VpnServerCommand::IpsecVirtualIp { map, state } => VpnServerChange::IpsecVirtualIp {
            name: map,
            enabled: state.enabled(),
        },
    };
    let session = Session::open(ctx, Permission::Write).await?;
    let operation = vpn_servers::plan_change(session.router(), &change)?;
    session
        .cli(&operation, vpn_servers::change_request(&operation)?)
        .await
}

/// Sets the IKE pre-shared key `name` from the usual secret sources.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: changes may apply before cancellation.
async fn ike_psk(ctx: &Ctx, name: &str) -> Outcome {
    let session = Session::open(ctx, Permission::Write).await?;
    let key_name = object(name)?;
    let psk = new_secret(ctx, name)?;
    let operation = server_secrets::plan_ike_psk(session.router(), key_name, psk)?;
    session
        .cli(&operation, vpn_clients::change_request(&operation)?)
        .await
}

/// Sets the VPN server password of the router account `user`.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: changes may apply before cancellation.
async fn password(ctx: &Ctx, user: &str) -> Outcome {
    let session = Session::open_for_account(ctx, Permission::ManageUsers, user).await?;
    let account = object(user)?;
    let password = new_secret(ctx, user)?;
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
