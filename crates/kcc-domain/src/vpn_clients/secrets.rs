//! Protected VPN credential writes and presence-only verification.
//!
//! Firmware 5.1 has no catalog command for OpenVPN credentials or embedded configuration.
//! Those writes are unsupported; the available OpenVPN commands only configure routing,
//! connection selection, and name servers.

use core::{result::Result as CoreResult, str::from_utf8};

use kcc_app::{
    permissions::Permission,
    workflow::{
        ChangeSet, CliCommand as ValidatedCli, PresencePredicate, VerificationSpec, WorkflowError,
    },
};
use kcc_catalog::Risk;
use kcc_rci::{ConfigKind, ObjectName};
use secrecy::{ExposeSecret as _, SecretString};
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
    let mut request = router
        .catalog
        .validate_secret(path, argument, secret)
        .map_err(|issues| DomainError::Validation { issues })?;
    drop(
        ValidatedCli::from_template(request.clone(), &template)
            .map_err(|_error| DomainError::InvalidCliToken)?,
    );
    request.value = json!({"line":template,"arguments":request.value});
    let mut verify = VerificationSpec::presence(
        Vec::new(),
        "vpn/credential".to_owned(),
        PresencePredicate::ConfigSecret,
    );
    verify.expected = json!(prefix);
    Ok(ChangeOp::new(
        vec![request],
        vec![verify],
        Risk::Write,
        Permission::Write,
        false,
    ))
}

/// Applies a credential and verifies only the stored payload's presence and length.
///
/// # Errors
/// Returns validation, dispatch, or presence verification failures without credential text.
// NOT cancel-safe: a router write may finish before the subsequent read-back.
pub async fn apply(
    changes: &mut ChangeSet,
    router: &RouterCtx,
    target: &CredentialTarget,
    secret: SecretString,
) -> CoreResult<(), WorkflowError> {
    let operation =
        plan(router, target, secret).map_err(|_error| WorkflowError::InvalidResponse)?;
    let request = change::request(&operation).map_err(|_error| WorkflowError::InvalidResponse)?;
    drop(changes.apply_cli(request).await?);
    let bytes = router.client.download_config(ConfigKind::Running).await?;
    let text = from_utf8(bytes.expose_secret()).map_err(|_error| WorkflowError::InvalidResponse)?;
    let (_, _, prefix) = target.binding();
    let mut contexts = Vec::<(usize, &str)>::new();
    let present = text.lines().any(|line| {
        let trimmed = line.trim_start();
        if trimmed.starts_with('!') || trimmed.is_empty() {
            return false;
        }
        let indent = line.len().saturating_sub(trimmed.len());
        contexts.retain(|(depth, _)| *depth < indent);
        let remaining = contexts
            .iter()
            .try_fold(prefix.as_str(), |rest, (_, context)| {
                rest.strip_prefix(context)?.strip_prefix(' ')
            });
        let present = remaining
            .and_then(|rest| trimmed.strip_prefix(rest))
            .and_then(|tail| tail.strip_prefix(' '))
            .map(|payload| payload.strip_prefix("ns3 ").unwrap_or(payload))
            .is_some_and(|payload| !payload.is_empty() && payload.len() <= 512);
        contexts.push((indent, trimmed));
        present
    });
    if !present {
        return Err(WorkflowError::VerificationFailed {
            field: "vpn/credential".to_owned(),
        });
    }
    Ok(())
}
