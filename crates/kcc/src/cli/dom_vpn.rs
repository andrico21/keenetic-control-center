//! VPN client writes: typed `VpnClientChange`s, secret-safe credentials and the WireGuard
//! import.

use std::{io::Read as _, path::Path};

use kcc_app::{
    permissions::Permission,
    secrets::files::{SecretFileError, open_secret_file},
};
use kcc_catalog::Risk;
use kcc_domain::{
    interfaces,
    vpn_clients::{
        self, VpnClientChange, WireGuardAsc,
        secrets::{self as client_secrets, CredentialTarget},
    },
};
use kcc_i18n::keys;
use zeroize::Zeroizing;

use super::{
    args_dom_family::Family,
    args_dom_vpn::{
        CryptoKind, ProtocolKind, RoutesKind, SecretKind, VpnSecretCommand, VpnWriteCommand,
    },
    args_domains_wire::VpnCommand,
    change::{Gate, applied},
    context::Ctx,
    dom_net::new_secret,
    dom_wire::{self, object},
    domains::Session,
    exit::{Exit, Failure, Outcome},
    secret::secret_file_failure,
};

/// Largest WireGuard configuration file read.
const MAX_CONF_BYTES: u64 = 64 * 1024;

/// Runs a `vpn` command: reads, configuration changes, or key material.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: changes may apply before cancellation.
pub(crate) async fn vpn(
    ctx: &Ctx,
    command: Family<VpnCommand, Family<VpnWriteCommand, VpnSecretCommand>>,
) -> Outcome {
    match command {
        Family::Base(sub) => dom_wire::vpn(ctx, sub).await,
        Family::Writes(Family::Base(sub)) => {
            let session = Session::open(ctx, Permission::Write).await?;
            let operation = vpn_clients::plan_change(session.router(), &change(sub)).await?;
            session
                .cli(&operation, vpn_clients::change_request(&operation)?)
                .await
        }
        Family::Writes(Family::Writes(sub)) => secrets(ctx, sub).await,
    }
}

/// Runs a credential write or a WireGuard import.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: changes may apply before cancellation.
async fn secrets(ctx: &Ctx, command: VpnSecretCommand) -> Outcome {
    let session = Session::open(ctx, Permission::Write).await?;
    match command {
        VpnSecretCommand::WireguardImport { name, file } => {
            let text = read_conf(&file)?;
            let config = vpn_clients::parse_wireguard_config(&text)
                .map_err(|error| Failure::text(Exit::Validation, &error))?;
            let taken = interfaces::read_interfaces(session.router())
                .await?
                .contains_key(&name);
            if taken {
                return Err(Failure::message(
                    Exit::Conflict,
                    keys::CLI_NAME_TAKEN,
                    &[("name", &name)],
                ));
            }
            let operation =
                vpn_clients::plan_wireguard_import(session.router(), &name, &config).await?;
            session
                .cli(&operation, vpn_clients::change_request(&operation)?)
                .await
        }
        VpnSecretCommand::Secret { kind, name } => {
            let object_name = object(&name)?;
            let target = match kind {
                SecretKind::Ppp => CredentialTarget::Ppp(object_name),
                SecretKind::Ipsec => CredentialTarget::IpsecInterface(object_name),
                SecretKind::Ike => CredentialTarget::Ike(object_name),
                SecretKind::ProfilePsk => CredentialTarget::ProfilePreshared(object_name),
                SecretKind::ProfileXauth => CredentialTarget::ProfileXauth(object_name),
            };
            let value = new_secret(ctx, &name)?;
            let gate = Gate::new(Risk::Write, Permission::Write, false);
            session
                .change(gate, async move |changes, router| {
                    client_secrets::apply(changes, router, &target, value).await?;
                    Ok(applied(true))
                })
                .await
        }
    }
}

/// Reads a WireGuard configuration of at most [`MAX_CONF_BYTES`] into wiped memory.
///
/// # Errors
///
/// Returns the exit-3 failure of a file others can read, I/O failures (exit 1), or a
/// validation failure for a larger file.
fn read_conf(path: &Path) -> Outcome<Zeroizing<String>> {
    let mut text = Zeroizing::new(String::new());
    let _: usize = open_secret_file(path)
        .map_err(|error| match error {
            SecretFileError::Read { path: _, source } => Failure::from(source),
            other @ (SecretFileError::Permissions { path: _ } | _) => secret_file_failure(&other),
        })?
        .take(MAX_CONF_BYTES.saturating_add(1))
        .read_to_string(&mut text)?;
    if u64::try_from(text.len()).unwrap_or(u64::MAX) > MAX_CONF_BYTES {
        return Err(Failure::text(
            Exit::Validation,
            "the WireGuard configuration is larger than 64 KiB",
        ));
    }
    Ok(text)
}

/// The typed VPN client change of the command line.
fn change(command: VpnWriteCommand) -> VpnClientChange {
    match command {
        VpnWriteCommand::Create { name } => VpnClientChange::Create { name },
        VpnWriteCommand::Delete { name } => VpnClientChange::Delete { name },
        VpnWriteCommand::Enable { name, state } => VpnClientChange::Enabled {
            name,
            enabled: state.enabled(),
        },
        VpnWriteCommand::WireguardGenerateKey { name } => {
            VpnClientChange::GenerateWireGuardPrivateKey { name }
        }
        VpnWriteCommand::WireguardListenPort { name, port } => {
            VpnClientChange::WireGuardListenPort { name, port }
        }
        VpnWriteCommand::WireguardPeer { name, public_key } => {
            VpnClientChange::WireGuardPeer { name, public_key }
        }
        VpnWriteCommand::WireguardEndpoint {
            name,
            public_key,
            address,
            port,
        } => VpnClientChange::WireGuardEndpoint {
            name,
            public_key,
            address,
            port,
        },
        VpnWriteCommand::WireguardAllowedIp {
            name,
            public_key,
            address,
            mask,
        } => VpnClientChange::WireGuardAllowedIp {
            name,
            public_key,
            address,
            mask,
        },
        VpnWriteCommand::WireguardKeepalive {
            name,
            public_key,
            seconds,
        } => VpnClientChange::WireGuardKeepalive {
            name,
            public_key,
            seconds,
        },
        VpnWriteCommand::WireguardAsc { name, values } => VpnClientChange::WireGuardAsc {
            name,
            asc: WireGuardAsc::new(values),
        },
        VpnWriteCommand::ZerotierNetwork { name, network_id } => {
            VpnClientChange::ZeroTierNetwork { name, network_id }
        }
        VpnWriteCommand::AcceptRoutes { name, kind, state } => match kind {
            RoutesKind::Zerotier => VpnClientChange::ZeroTierAcceptRoutes {
                name,
                enabled: state.enabled(),
            },
            RoutesKind::Openvpn => VpnClientChange::OpenVpnAcceptRoutes {
                name,
                enabled: state.enabled(),
            },
        },
        VpnWriteCommand::Protocol {
            name,
            kind,
            protocol,
        } => match kind {
            ProtocolKind::Openconnect => VpnClientChange::OpenConnectProtocol { name, protocol },
            ProtocolKind::Proxy => VpnClientChange::ProxyProtocol { name, protocol },
        },
        VpnWriteCommand::ProxyUpstream { name, host, port } => {
            VpnClientChange::ProxyUpstream { name, host, port }
        }
        VpnWriteCommand::Crypto { kind, name } => match kind {
            CryptoKind::IkePolicy => VpnClientChange::IkePolicy { name },
            CryptoKind::IkeProposal => VpnClientChange::IkeProposal { name },
            CryptoKind::IpsecProfile => VpnClientChange::IpsecProfile { name },
            CryptoKind::IpsecTransform => VpnClientChange::IpsecTransformSet { name },
            CryptoKind::CryptoMap => VpnClientChange::CryptoMap { name },
        },
    }
}
