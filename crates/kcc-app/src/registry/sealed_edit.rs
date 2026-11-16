//! A router profile update that seals new secrets for it as one change.
//!
//! The sealed record paths depend only on the router id, so sealing a new secret rebinds
//! it to whatever profile is stored. [`update_sealed`] therefore keeps the previous
//! sealed bytes of every kind and puts them back unless the new profile was stored.

use core::mem::DropGuard;

use secrecy::SecretString;

use super::{ManagedRouterProfile, RegistryError, RouterRegistry};
use crate::{
    credentials::{CredentialKind, CredentialStore, rollback::SealedRecords},
    permissions::Role,
};

/// A profile after an edit and the secrets the edit seals for it.
#[derive(Debug)]
#[non_exhaustive]
pub struct SealedEdit<'secrets> {
    /// The profile after the edit, already pointing at the sealed records.
    pub profile: ManagedRouterProfile,
    /// The new secrets, each with its kind.
    pub secrets: &'secrets [(CredentialKind, SecretString)],
}

impl<'secrets> SealedEdit<'secrets> {
    /// The edit storing `profile` with `secrets` sealed.
    #[inline]
    #[must_use]
    pub const fn new(
        profile: ManagedRouterProfile,
        secrets: &'secrets [(CredentialKind, SecretString)],
    ) -> Self {
        Self { profile, secrets }
    }
}

/// Validates the edited profile, seals its secrets and stores it.
///
/// Nothing is sealed for a profile that does not validate. When sealing or the update
/// fails, the sealed record of every kind is put back byte for byte (a kind that had no
/// record has none again), so the stored profile keeps signing in with its old secrets.
/// The rollback also runs when the future is dropped; then it keeps the new records only
/// when the registry already holds the edited profile and that profile differs from the
/// one before the edit. A concurrent change of the same router between the snapshot and
/// the rollback is not detected.
///
/// # Errors
///
/// Returns the validation, credential, permission or registry failure.
// NOT cancel-safe: cancelled inside the registry update, the profile may be stored while
// the client cache is not refreshed; the sealed records follow the stored profile.
#[inline]
pub async fn update_sealed(
    registry: &RouterRegistry,
    store: &CredentialStore,
    role: &Role,
    edit: SealedEdit<'_>,
) -> Result<(), RegistryError> {
    let SealedEdit { profile, secrets } = edit;
    profile.validate()?;
    if secrets.is_empty() {
        return registry.update(role, profile).await;
    }
    let before = registry.get(&profile.id)?.profile;
    let edited = profile.clone();
    let snapshot = SealedRecords::take(store, &profile.id)?;
    let staged = DropGuard::new(snapshot, |records: SealedRecords| {
        let stored = registry.get(&edited.id).map(|entry| entry.profile);
        let landed = edited != before && stored.is_ok_and(|current| current == edited);
        if landed {
            return;
        }
        if let Err(error) = records.restore(store) {
            tracing::error!(
                router = %edited.id,
                %error,
                "sealed router credentials could not be restored"
            );
        }
    });
    for (kind, secret) in secrets {
        store.store(&profile.id, *kind, secret)?;
    }
    registry.update(role, profile).await?;
    drop(DropGuard::dismiss(staged));
    Ok(())
}
