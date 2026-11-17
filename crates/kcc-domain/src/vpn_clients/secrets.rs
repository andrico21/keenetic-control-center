//! Protected VPN credential writes and presence-only verification.
//!
//! Firmware 5.1 has no catalog command for OpenVPN credentials or embedded configuration.
//! Those writes are unsupported; the available OpenVPN commands only configure routing,
//! connection selection, and name servers.

use core::result::Result as CoreResult;

use kcc_app::{
    permissions::Permission,
    workflow::{
        ChangeSet, CliChangeResult, CliCommand as ValidatedCli, PresencePredicate,
        VerificationSpec, WorkflowError,
    },
};
use kcc_catalog::Risk;
use kcc_rci::ObjectName;
use secrecy::SecretString;
use serde_json::json;

use super::change;
use crate::{ChangeOp, DomainError, Result, RouterCtx};

/// A catalog-backed VPN secret destination.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum CredentialTarget {
    /// PPP authentication shared by L2TP, PPTP, and SSTP clients.
    Ppp(ObjectName),
    /// Interface IPsec preshared key.
    IpsecInterface(ObjectName),
    /// Named IKE key accepting any remote identity.
    Ike(ObjectName),
    /// Named IPsec profile preshared key.
    ProfilePreshared(ObjectName),
    /// Named IPsec profile `XAuth` password.
    ProfileXauth(ObjectName),
    /// WireGuard interface obfuscation key.
    WireGuardObfuscation(ObjectName),
    /// WireGuard peer obfuscation key, selected by interface and peer public key.
    WireGuardPeerObfuscation(ObjectName, ObjectName),
}

impl CredentialTarget {
    /// Returns the command, declared slot, and full contextual prefix.
    pub(crate) fn binding(&self) -> (&'static str, &'static str, String) {
        match self {
            Self::Ppp(name) => (
                "interface authentication password",
                "password",
                format!("interface {name} authentication password"),
            ),
            Self::IpsecInterface(name) => (
                "interface ipsec preshared-key",
                "key",
                format!("interface {name} ipsec preshared-key"),
            ),
            Self::Ike(name) => ("crypto ike key", "psk", format!("crypto ike key {name}")),
            Self::ProfilePreshared(name) => (
                "crypto ipsec profile preshared-key",
                "preshare-key",
                format!("crypto ipsec profile {name} preshared-key"),
            ),
            Self::ProfileXauth(name) => (
                "crypto ipsec profile xauth-password",
                "password",
                format!("crypto ipsec profile {name} xauth-password"),
            ),
            Self::WireGuardObfuscation(name) => (
                "interface wireguard obfs-key",
                "obfs-key",
                format!("interface {name} wireguard obfs-key"),
            ),
            Self::WireGuardPeerObfuscation(name, peer) => (
                "interface wireguard peer obfs-key",
                "obfs-key",
                format!("interface {name} wireguard peer {peer} obfs-key"),
            ),
        }
    }
}

/// Plans a credential without retaining a printable secret or sending a router request.
///
/// # Errors
///
/// Returns an error when an argument cannot be one safe router CLI word
/// ([`DomainError::InvalidCliToken`]), or when the catalog refuses a planned request
/// ([`DomainError::Validation`]).
#[inline]
pub fn plan(
    router: &RouterCtx,
    target: &CredentialTarget,
    secret: SecretString,
) -> Result<ChangeOp> {
    let (path, argument, prefix) = target.binding();
    let suffix = match target {
        CredentialTarget::Ike(_) => " any",
        CredentialTarget::Ppp(_)
        | CredentialTarget::IpsecInterface(_)
        | CredentialTarget::ProfilePreshared(_)
        | CredentialTarget::ProfileXauth(_)
        | CredentialTarget::WireGuardObfuscation(_)
        | CredentialTarget::WireGuardPeerObfuscation(_, _) => "",
    };
    let template = format!("{prefix} {{/{argument}}}{suffix}");
    let request = router
        .catalog
        .validate_secret(path, argument, secret)
        .map_err(|issues| DomainError::Validation { issues })?;
    let command = ValidatedCli::from_template(request, &template)
        .map_err(|_error| DomainError::InvalidCliToken)?;
    let mut verify = VerificationSpec::presence(
        Vec::new(),
        "vpn/credential".to_owned(),
        PresencePredicate::ConfigSecret,
    );
    verify.expected = json!(prefix);
    let mut operation = ChangeOp::new(
        Vec::new(),
        vec![verify],
        Risk::Write,
        Permission::Write,
        false,
    );
    operation.push(command);
    Ok(operation)
}

/// Applies a credential and returns the change's result, its audit receipt included.
///
/// The change workflow verifies only the stored payload's presence and length (the plan's
/// `ConfigSecret` check) before the audit entry.
///
/// # Errors
/// Returns validation, dispatch, or presence verification failures without credential text.
// NOT cancel-safe: a router write may finish before the subsequent read-back.
#[inline]
pub async fn apply(
    changes: &mut ChangeSet,
    router: &RouterCtx,
    target: &CredentialTarget,
    secret: SecretString,
) -> CoreResult<CliChangeResult, WorkflowError> {
    let operation = plan(router, target, secret)?;
    let request = change::request(&operation)?;
    changes.apply_cli(request).await
}
