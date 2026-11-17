//! VPN client commands: the list, typed `VpnClientChange`s, secret-safe credentials and
//! the WireGuard import.

use std::{
    io::Read as _,
    path::{Path, PathBuf},
};

use kcc_app::{
    permissions::Permission,
    secrets::files::{SecretFileError, open_secret_file},
};
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
    args_dom_vpn::{CryptoKind, ProtocolKind, RoutesKind, SecretKind, VpnCommand},
    context::Ctx,
    dom_net::new_secret,
    dom_wire::object,
    domains::Session,
    exit::{Exit, Failure, Outcome},
    secret::secret_file_failure,
};

/// Largest WireGuard configuration file read.
const MAX_CONF_BYTES: u64 = 64 * 1024;

/// What a `vpn` command asks for.
enum Request {
    /// The VPN connections.
    List,
    /// A WireGuard tunnel from a `.conf` file.
    Import {
        /// New interface name.
        name: String,
        /// The configuration file.
        file: PathBuf,
    },
    /// A credential read from the usual secret sources.
    Secret {
        /// Credential kind.
        kind: SecretKind,
        /// Interface, IKE key or IPsec profile name.
        name: String,
    },
    /// A typed configuration change.
    Change(VpnClientChange),
}

/// Runs a `vpn` command: reads, configuration changes, or key material.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: changes may apply before cancellation.
pub(crate) async fn vpn(ctx: &Ctx, command: VpnCommand) -> Outcome {
    let change = match request(command) {
        Request::List => {
            let session = Session::open(ctx, Permission::Read).await?;
            return session.show(&vpn_clients::read_clients(session.router()).await?);
        }
        Request::Import { name, file } => return import(ctx, &name, &file).await,
        Request::Secret { kind, name } => return secret(ctx, kind, &name).await,
        Request::Change(change) => change,
    };
    let session = Session::open(ctx, Permission::Write).await?;
    let operation = vpn_clients::plan_change(session.router(), &change).await?;
    session
        .cli(&operation, vpn_clients::change_request(&operation)?)
        .await
}

/// Creates a WireGuard tunnel `name` from the configuration `file`.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: changes may apply before cancellation.
async fn import(ctx: &Ctx, name: &str, file: &Path) -> Outcome {
    let session = Session::open(ctx, Permission::Write).await?;
    let text = read_conf(file)?;
    let config = vpn_clients::parse_wireguard_config(&text)
        .map_err(|error| Failure::text(Exit::Validation, &error))?;
    let taken = interfaces::read_interfaces(session.router())
        .await?
        .contains_key(name);
    if taken {
        return Err(Failure::message(
            Exit::Conflict,
            keys::CLI_NAME_TAKEN,
            &[("name", name)],
        ));
    }
    let operation = vpn_clients::plan_wireguard_import(session.router(), name, &config).await?;
    session
        .cli(&operation, vpn_clients::change_request(&operation)?)
        .await
}

/// Sets the credential `kind` of `name` from the usual secret sources.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: changes may apply before cancellation.
async fn secret(ctx: &Ctx, kind: SecretKind, name: &str) -> Outcome {
    let session = Session::open(ctx, Permission::Write).await?;
    let object_name = object(name)?;
    let target = match kind {
        SecretKind::Ipsec => CredentialTarget::IpsecInterface(object_name),
        SecretKind::Ike => CredentialTarget::Ike(object_name),
        SecretKind::ProfilePsk => CredentialTarget::ProfilePreshared(object_name),
        SecretKind::ProfileXauth => CredentialTarget::ProfileXauth(object_name),
    };
    let value = new_secret(ctx, name)?;
    let operation = client_secrets::plan(session.router(), &target, value)?;
    session
        .cli(&operation, vpn_clients::change_request(&operation)?)
        .await
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
        return Err(Failure::message(
            Exit::Validation,
            keys::CLI_WIREGUARD_CONF_TOO_LARGE,
            &[],
        ));
    }
    Ok(text)
}

/// What `command` asks for: a read, an import, a credential, or the typed change.
fn request(command: VpnCommand) -> Request {
    let change = match command {
        VpnCommand::List => return Request::List,
        VpnCommand::WireguardImport { name, file } => return Request::Import { name, file },
        VpnCommand::Secret { kind, name } => return Request::Secret { kind, name },
        VpnCommand::Create { name } => VpnClientChange::Create { name },
        VpnCommand::Delete { name } => VpnClientChange::Delete { name },
        VpnCommand::Enable { name, state } => VpnClientChange::Enabled {
            name,
            enabled: state.enabled(),
        },
        VpnCommand::WireguardGenerateKey { name } => {
            VpnClientChange::GenerateWireGuardPrivateKey { name }
        }
        VpnCommand::WireguardListenPort { name, port } => {
            VpnClientChange::WireGuardListenPort { name, port }
        }
        VpnCommand::WireguardPeer { name, public_key } => {
            VpnClientChange::WireGuardPeer { name, public_key }
        }
        VpnCommand::WireguardEndpoint {
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
        VpnCommand::WireguardAllowedIp {
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
        VpnCommand::WireguardKeepalive {
            name,
            public_key,
            seconds,
        } => VpnClientChange::WireGuardKeepalive {
            name,
            public_key,
            seconds,
        },
        VpnCommand::WireguardAsc { name, values } => VpnClientChange::WireGuardAsc {
            name,
            asc: WireGuardAsc::new(values),
        },
        VpnCommand::ZerotierNetwork { name, network_id } => {
            VpnClientChange::ZeroTierNetwork { name, network_id }
        }
        VpnCommand::AcceptRoutes { name, kind, state } => match kind {
            RoutesKind::Zerotier => VpnClientChange::ZeroTierAcceptRoutes {
                name,
                enabled: state.enabled(),
            },
            RoutesKind::Openvpn => VpnClientChange::OpenVpnAcceptRoutes {
                name,
                enabled: state.enabled(),
            },
        },
        VpnCommand::Protocol {
            name,
            kind,
            protocol,
        } => match kind {
            ProtocolKind::Openconnect => VpnClientChange::OpenConnectProtocol { name, protocol },
            ProtocolKind::Proxy => VpnClientChange::ProxyProtocol { name, protocol },
        },
        VpnCommand::ProxyUpstream { name, host, port } => {
            VpnClientChange::ProxyUpstream { name, host, port }
        }
        VpnCommand::Crypto { kind, name } => match kind {
            CryptoKind::IkePolicy => VpnClientChange::IkePolicy { name },
            CryptoKind::IkeProposal => VpnClientChange::IkeProposal { name },
            CryptoKind::IpsecProfile => VpnClientChange::IpsecProfile { name },
            CryptoKind::IpsecTransform => VpnClientChange::IpsecTransformSet { name },
            CryptoKind::CryptoMap => VpnClientChange::CryptoMap { name },
        },
    };
    Request::Change(change)
}
