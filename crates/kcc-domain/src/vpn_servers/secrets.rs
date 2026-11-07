//! VPN server credential writes and explicit permission-gated stored-secret reads.

use core::{result::Result as CoreResult, str::from_utf8};

use kcc_app::{
    permissions::{Permission, Role},
    registry::authorize,
    workflow::{ChangeSet, CliChangeRequest, WorkflowError},
};
use kcc_rci::{ConfigKind, ObjectName};
use secrecy::{ExposeSecret as _, SecretString};

use crate::{
    ChangeOp, DomainError, Result, RouterCtx, router_users,
    vpn_clients::secrets::{self as credentials, CredentialTarget},
};

/// Authorizes stored-secret reads against one router context.
///
/// Frontends must pass the registered router name and audit the reveal action.
/// Ordinary server reads never construct this gate or return secret values.
#[derive(Debug)]
#[non_exhaustive]
#[expect(
    clippy::module_name_repetitions,
    reason = "the explicit RevealSecrets gate name is part of the domain contract"
)]
pub struct RevealSecrets<'router> {
    /// Router to which the authorization applies.
    router: &'router RouterCtx,
}

impl<'router> RevealSecrets<'router> {
    /// Checks reveal permission and router scope before any router request.
    ///
    /// # Errors
    /// Returns permission denied when the role cannot reveal this router's secrets.
    pub fn authorize(role: &Role, name: &str, router: &'router RouterCtx) -> Result<Self> {
        authorize(role, Permission::RevealSecrets, name)
            .map_err(|_error| DomainError::PermissionDenied)?;
        Ok(Self { router })
    }

    /// Reads the stored representation without decoding NS3 or exposing it through Debug.
    ///
    /// # Errors
    /// Returns a value-free error on read or UTF-8 failure.
    // cancel-safe: only downloads the current configuration.
    pub async fn read_stored(&self, target: &CredentialTarget) -> Result<Option<SecretString>> {
        let bytes = self
            .router
            .client
            .download_config(ConfigKind::Running)
            .await?;
        let text =
            from_utf8(bytes.expose_secret()).map_err(|_error| DomainError::InvalidResponse)?;
        let (_, _, prefix) = target.binding();
        let mut contexts = Vec::<(usize, &str)>::new();
        for line in text.lines() {
            let trimmed = line.trim_start();
            if trimmed.starts_with('!') || trimmed.is_empty() {
                continue;
            }
            let indent = line.len().saturating_sub(trimmed.len());
            contexts.retain(|(depth, _)| *depth < indent);
            let remaining = contexts
                .iter()
                .try_fold(prefix.as_str(), |rest, (_, context)| {
                    rest.strip_prefix(context)?.strip_prefix(' ')
                });
            if let Some(payload) = remaining
                .and_then(|rest| trimmed.strip_prefix(rest))
                .and_then(|tail| tail.strip_prefix(' '))
            {
                let stored = match target {
                    CredentialTarget::Ike(_) => payload.strip_suffix(" any").unwrap_or(payload),
                    CredentialTarget::Ppp(_)
                    | CredentialTarget::IpsecInterface(_)
                    | CredentialTarget::ProfilePreshared(_)
                    | CredentialTarget::ProfileXauth(_)
                    | CredentialTarget::WireGuardObfuscation(_)
                    | CredentialTarget::WireGuardPeerObfuscation(_, _) => payload,
                };
                return Ok(Some(SecretString::from(stored)));
            }
            contexts.push((indent, trimmed));
        }
        Ok(None)
    }
}

/// Sets a router-account password used by VPN, SSTP, and OpenConnect servers.
/// Existing service-access tags are preserved; callers manage those separately.
pub fn plan_password(
    router: &RouterCtx,
    user: &ObjectName,
    password: SecretString,
) -> Result<ChangeOp> {
    router_users::plan_password(router, user.as_str(), password)
}

/// Converts a server-account password plan to its protected workflow request.
pub fn password_request(operation: &ChangeOp) -> Result<CliChangeRequest> {
    router_users::change_request(operation)
}

/// Sets and verifies the named IKE key used by an IPsec/IKEv2 server.
///
/// # Errors
/// Returns validation, dispatch, or presence verification failures.
// NOT cancel-safe: a write may complete before read-back.
pub async fn apply_ike_psk(
    changes: &mut ChangeSet,
    router: &RouterCtx,
    name: ObjectName,
    psk: SecretString,
) -> CoreResult<(), WorkflowError> {
    credentials::apply(changes, router, &CredentialTarget::Ike(name), psk).await
}
