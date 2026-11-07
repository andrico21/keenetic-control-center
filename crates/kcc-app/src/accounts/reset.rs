//! Permission and last-administrator policy for administrative password resets.

use secrecy::SecretString;

use super::{
    AccountError, AccountStore, UsersDocument, enabled_admin, hash_password, validate_password,
};
use crate::permissions::{Permission, Role};

/// Applies an administrative password reset.
///
/// # Errors
///
/// Returns the reset policy, password policy, hashing, encryption, or state error.
pub(super) fn password(
    store: &AccountStore,
    actor: (&str, &Role),
    username: &str,
    new_password: &SecretString,
) -> Result<bool, AccountError> {
    let (actor_username, actor_role) = actor;
    if !actor_role.grants(Permission::ManageUsers) {
        return Err(AccountError::PermissionDenied);
    }
    if actor_username == username {
        return Err(AccountError::SelfResetRequiresCurrentPassword);
    }
    validate_password(username, new_password)?;
    let hash = hash_password(new_password)?;
    let sealed = store.key.seal(username, &SecretString::from(hash))?;
    store.state.update(|document: &mut UsersDocument| {
        let actor_is_admin = document.users.iter().any(|account| {
            account.username == actor_username && enabled_admin(&account.role, account.disabled)
        });
        let Some(account) = document
            .users
            .iter_mut()
            .find(|candidate| candidate.username == username)
        else {
            return Ok(false);
        };
        if enabled_admin(&account.role, account.disabled) && !actor_is_admin {
            return Err(AccountError::AdminResetRequiresAdmin);
        }
        account.password_hash = sealed;
        account.failure_count = 0;
        account.lockout_until = None;
        account.must_change_password = true;
        Ok(true)
    })?
}
