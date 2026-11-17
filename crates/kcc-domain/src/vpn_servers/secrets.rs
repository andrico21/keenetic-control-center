//! VPN server credential writes.

use core::result::Result as CoreResult;

use kcc_app::workflow::{ChangeSet, CliChangeRequest, CliChangeResult, WorkflowError};
use kcc_rci::ObjectName;
use secrecy::SecretString;

use crate::{
    ChangeOp, Result, RouterCtx,
    router_users::{self, protection::OwnLogins},
    vpn_clients::secrets::{self as credentials, CredentialTarget},
};

/// Sets a router-account password used by VPN, SSTP, and OpenConnect servers.
/// Existing service-access tags are preserved; callers manage those separately.
///
/// # Errors
///
/// Returns an error when the catalog refuses a planned request
/// ([`crate::DomainError::Validation`]).
#[inline]
pub fn plan_password(
    router: &RouterCtx,
    user: &ObjectName,
    own: &OwnLogins,
    password: SecretString,
) -> Result<ChangeOp> {
    router_users::plan_password(router, user.as_str(), own, password)
}

/// Converts a server-account password plan to its protected workflow request.
///
/// # Errors
///
/// Returns `DomainError::InvalidResponse` when the plan holds no request, a request lacks the
/// account name or a tag, or the password command cannot be bound to its template or given its
/// read-back checks, and `DomainError::Workflow` when a rendered user line does not match its
/// request.
#[inline]
pub fn password_request(operation: &ChangeOp) -> Result<CliChangeRequest> {
    router_users::change_request(operation)
}

/// Plans the named IKE key used by an IPsec/IKEv2 server without sending anything.
///
/// # Errors
///
/// Returns an error when the name or the key cannot be one safe router CLI word
/// ([`crate::DomainError::InvalidCliToken`]), or when the catalog refuses the planned
/// request ([`crate::DomainError::Validation`]).
#[inline]
pub fn plan_ike_psk(router: &RouterCtx, name: ObjectName, psk: SecretString) -> Result<ChangeOp> {
    credentials::plan(router, &CredentialTarget::Ike(name), psk)
}

/// Sets and verifies the named IKE key used by an IPsec/IKEv2 server; returns the
/// change's result, its audit receipt included.
///
/// # Errors
/// Returns validation, dispatch, or presence verification failures.
// NOT cancel-safe: a write may complete before read-back.
#[inline]
pub async fn apply_ike_psk(
    changes: &mut ChangeSet,
    router: &RouterCtx,
    name: ObjectName,
    psk: SecretString,
) -> CoreResult<CliChangeResult, WorkflowError> {
    credentials::apply(changes, router, &CredentialTarget::Ike(name), psk).await
}
