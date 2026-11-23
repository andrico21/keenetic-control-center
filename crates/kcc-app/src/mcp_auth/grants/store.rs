//! The grant operations: issue on code redemption, refresh with rotation and reuse
//! detection, revocation.

extern crate alloc;

use alloc::sync::Arc;
use core::{mem, time::Duration};

use secrecy::{ExposeSecret as _, SecretString};

use super::{
    Grant, GrantError, GrantStore, GrantsDocument, IssuedGrant, Located, MAX_GRANTS,
    MAX_GRANTS_PER_ACCOUNT, MAX_PREVIOUS, Refresh, RefreshRequest, password_hash,
};
use crate::{
    accounts::{Clock, standing::PasswordFingerprint},
    mcp_auth::{clients::ClientsDocument, digest_hex, new_id, new_secret, pending::AuthorizedCode},
    persist::{Edit, StateStore},
};

impl GrantStore {
    /// A store in `state` on `clock` whose refresh tokens live `refresh_ttl`.
    #[inline]
    #[must_use]
    pub fn new(state: StateStore, clock: Arc<dyn Clock>, refresh_ttl: Duration) -> Self {
        Self {
            state,
            clock,
            refresh_ttl,
        }
    }

    /// Creates the grant for a redeemed `code`, bound to the account's current password
    /// `fingerprint`, and answers it with its first refresh token. Records the grant on
    /// the client first, so a purge keeps the client.
    ///
    /// # Errors
    ///
    /// [`GrantError::UnknownClient`], [`GrantError::AccountLimit`],
    /// [`GrantError::TotalLimit`], or a storage or RNG failure.
    #[inline]
    pub fn issue(
        &self,
        code: &AuthorizedCode,
        fingerprint: &PasswordFingerprint,
    ) -> Result<IssuedGrant, GrantError> {
        let now = self.clock.unix_seconds();
        let refresh = new_secret()?;
        let grant = Grant {
            id: new_id()?,
            account: code.account().to_owned(),
            client: code.client_id().to_owned(),
            resource: code.resource().to_owned(),
            created_at: now,
            last_used_at: now,
            password: password_hash(fingerprint),
            revoked: false,
            refresh: Refresh {
                current: digest_hex(refresh.expose_secret().as_bytes()),
                expires_at: now.saturating_add(self.refresh_ttl.as_secs()),
                previous: Vec::new(),
            },
        };
        let known = self
            .state
            .update_if_changed(|clients: &mut ClientsDocument| {
                if clients.granted(&grant.client, now) {
                    Edit::Changed(true)
                } else {
                    Edit::Unchanged(false)
                }
            })?;
        if !known {
            return Err(GrantError::UnknownClient);
        }
        self.state
            .update_if_changed(|document: &mut GrantsDocument| {
                let purged = document.purge(now);
                let held = document
                    .grants
                    .iter()
                    .filter(|other| other.account == grant.account)
                    .count();
                let refusal = if held >= MAX_GRANTS_PER_ACCOUNT {
                    Some(GrantError::AccountLimit)
                } else if document.grants.len() >= MAX_GRANTS {
                    Some(GrantError::TotalLimit)
                } else {
                    None
                };
                match (refusal, purged) {
                    (Some(error), true) => Edit::Changed(Err(error)),
                    (Some(error), false) => Edit::Unchanged(Err(error)),
                    (None, _) => {
                        document.grants.push(grant.clone());
                        Edit::Changed(Ok(()))
                    }
                }
            })??;
        Ok(IssuedGrant { grant, refresh })
    }

    /// Rotates the refresh token of `request`, after checking that the grant is live, the
    /// client and resource are its own, and that `standing` answers the account's
    /// current password fingerprint (`None` for an account that may not sign in now, such
    /// as a disabled one or one that must change its password).
    ///
    /// # Errors
    ///
    /// [`GrantError::Unknown`]; [`GrantError::Reused`] for a rotated token, which revokes
    /// the grant; [`GrantError::Revoked`], [`GrantError::Expired`],
    /// [`GrantError::Client`], [`GrantError::Resource`] or [`GrantError::Account`], which
    /// leave the token usable; or a storage or RNG failure.
    #[inline]
    pub fn refresh(
        &self,
        request: &RefreshRequest<'_>,
        standing: &dyn Fn(&str) -> Option<PasswordFingerprint>,
    ) -> Result<IssuedGrant, GrantError> {
        let now = self.clock.unix_seconds();
        let presented = digest_hex(request.token.expose_secret().as_bytes());
        let next = new_secret()?;
        let next_digest = digest_hex(next.expose_secret().as_bytes());
        let expires_at = now.saturating_add(self.refresh_ttl.as_secs());
        let grant = self
            .state
            .update_if_changed(|document: &mut GrantsDocument| {
                let located = document.locate(&presented);
                let (Located::Current(index) | Located::Previous(index)) = located else {
                    return Edit::Unchanged(Err(GrantError::Unknown));
                };
                let Some(grant) = document.grants.get_mut(index) else {
                    return Edit::Unchanged(Err(GrantError::Unknown));
                };
                if matches!(located, Located::Previous(_)) {
                    let first = !grant.revoked;
                    grant.revoked = true;
                    return if first {
                        Edit::Changed(Err(GrantError::Reused))
                    } else {
                        Edit::Unchanged(Err(GrantError::Reused))
                    };
                }
                if let Err(error) = refreshable(grant, request, now, standing) {
                    return Edit::Unchanged(Err(error));
                }
                let rotated = mem::replace(&mut grant.refresh.current, next_digest.clone());
                grant.refresh.previous.push(rotated);
                let excess = grant.refresh.previous.len().saturating_sub(MAX_PREVIOUS);
                drop(grant.refresh.previous.drain(..excess));
                grant.refresh.expires_at = expires_at;
                grant.last_used_at = now;
                Edit::Changed(Ok(grant.clone()))
            })??;
        Ok(IssuedGrant {
            grant,
            refresh: next,
        })
    }

    /// Revokes grant `id`; `false` when there is no such live grant.
    ///
    /// # Errors
    ///
    /// A storage failure.
    #[inline]
    pub fn revoke(&self, id: &str) -> Result<bool, GrantError> {
        Ok(self
            .state
            .update_if_changed(|document: &mut GrantsDocument| {
                revoke_where(document, |grant| grant.id == id)
            })?)
    }

    /// Revokes the grant holding refresh token `token` (current or rotated) when it
    /// belongs to `client_id` (RFC 7009); `false` otherwise.
    ///
    /// # Errors
    ///
    /// A storage failure.
    #[inline]
    pub fn revoke_token(&self, token: &SecretString, client_id: &str) -> Result<bool, GrantError> {
        let presented = digest_hex(token.expose_secret().as_bytes());
        Ok(self
            .state
            .update_if_changed(|document: &mut GrantsDocument| {
                let (Located::Current(index) | Located::Previous(index)) =
                    document.locate(&presented)
                else {
                    return Edit::Unchanged(false);
                };
                let id = document
                    .grants
                    .get(index)
                    .filter(|grant| grant.client == client_id)
                    .map(|grant| grant.id.clone());
                revoke_where(document, |grant| Some(&grant.id) == id.as_ref())
            })?)
    }

    /// The stored grants.
    ///
    /// # Errors
    ///
    /// A storage failure.
    #[inline]
    pub fn document(&self) -> Result<GrantsDocument, GrantError> {
        Ok(self.state.read()?.unwrap_or_default())
    }
}

/// Revokes the first live grant `matches` selects.
fn revoke_where<F>(document: &mut GrantsDocument, matches: F) -> Edit<bool>
where
    F: Fn(&Grant) -> bool,
{
    document
        .grants
        .iter_mut()
        .find(|grant| !grant.revoked && matches(grant))
        .map_or(Edit::Unchanged(false), |grant| {
            grant.revoked = true;
            Edit::Changed(true)
        })
}

/// Checks that `grant` may be refreshed by `request` at `now`.
///
/// # Errors
///
/// The first refusal in the order revoked, expired, client, resource, account.
fn refreshable(
    grant: &Grant,
    request: &RefreshRequest<'_>,
    now: u64,
    standing: &dyn Fn(&str) -> Option<PasswordFingerprint>,
) -> Result<(), GrantError> {
    if grant.revoked {
        return Err(GrantError::Revoked);
    }
    if now >= grant.refresh.expires_at {
        return Err(GrantError::Expired);
    }
    if grant.client != request.client_id {
        return Err(GrantError::Client);
    }
    if request
        .resource
        .is_some_and(|resource| resource != grant.resource)
    {
        return Err(GrantError::Resource);
    }
    match standing(&grant.account) {
        Some(fingerprint) if grant.password_matches(&fingerprint) => Ok(()),
        Some(_) | None => Err(GrantError::Account),
    }
}
