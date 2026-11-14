//! The audit record of router-profile changes made in the Web UI.

use kcc_app::{credentials::CredentialKind, registry::ManagedRouterProfile, settings::RouterTls};
use serde_json::json;

use crate::{WebState, authz::CurrentUser, page_kit::audit::Record};

/// A router-profile change made in the Web UI, as the audit log records it.
pub(crate) enum ProfileAction<'profile> {
    /// A profile was added with the credentials of `credentials`.
    Create {
        /// The new profile.
        profile: &'profile ManagedRouterProfile,
        /// The kinds sealed for it.
        credentials: &'profile [CredentialKind],
    },
    /// A profile was changed.
    Update {
        /// The profile after the change.
        profile: &'profile ManagedRouterProfile,
        /// The kinds sealed or removed.
        credentials: &'profile [CredentialKind],
    },
    /// A profile and its stored credentials were removed.
    Delete(&'profile ManagedRouterProfile),
}

impl ProfileAction<'_> {
    /// The audit action id, the changed profile and the names of its changed credential
    /// kinds, in audit order.
    fn parts(&self) -> (&'static str, &ManagedRouterProfile, Vec<&'static str>) {
        let (action, profile) = match *self {
            Self::Create {
                profile,
                credentials: _,
            } => ("router.profile_create", profile),
            Self::Update {
                profile,
                credentials: _,
            } => ("router.profile_update", profile),
            Self::Delete(profile) => ("router.profile_delete", profile),
        };
        let names = CredentialKind::ALL
            .into_iter()
            .filter(|kind| match *self {
                Self::Create {
                    profile: _,
                    credentials,
                }
                | Self::Update {
                    profile: _,
                    credentials,
                } => credentials.contains(kind),
                Self::Delete(stored) => stored.credential_path(*kind).is_some(),
            })
            .map(CredentialKind::audit_name)
            .collect();
        (action, profile, names)
    }
}

/// Appends a router-profile audit event naming the changed credential kinds, never a
/// credential value.
// NOT cancel-safe: an abandoned append may still be written.
pub(crate) async fn audit(state: &WebState, user: &CurrentUser, change: ProfileAction<'_>) {
    let (action, profile, credentials) = change.parts();
    let tls = match &profile.tls {
        RouterTls::PinSha256(_) => "pinned",
        RouterTls::Verify | _ => "verify",
    };
    Record::on_router(action, &profile.id, profile.id.clone())
        .with_params(json!({
            "url": profile.url.as_str(),
            "login": profile.login,
            "tls": tls,
            "tags": profile.tags,
            "test_device": profile.test_device,
            "credentials": credentials,
        }))
        .append(state, user, "success")
        .await;
}
