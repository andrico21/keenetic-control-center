//! VPN server credential writes.

use core::result::Result as CoreResult;

use kcc_app::workflow::{ChangeSet, CliChangeRequest, WorkflowError};
use kcc_rci::ObjectName;
use secrecy::SecretString;

use crate::{
    ChangeOp, Result, RouterCtx,
    router_users::{self, protection::OwnLogins},
    vpn_clients::secrets::{self as credentials, CredentialTarget},
};

/// Sets a router-account password used by VPN, SSTP, and OpenConnect servers.
/// Existing service-access tags are preserved; callers manage those separately.
pub fn plan_password(
    router: &RouterCtx,
    user: &ObjectName,
    own: &OwnLogins,
    password: SecretString,
) -> Result<ChangeOp> {
    router_users::plan_password(router, user.as_str(), own, password)
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
