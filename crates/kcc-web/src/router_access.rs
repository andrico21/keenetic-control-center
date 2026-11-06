//! The audit record of router-profile changes made in the Web UI.

use kcc_app::{registry::ManagedRouterProfile, settings::RouterTls};
use serde_json::json;

use crate::{WebState, authz::CurrentUser, page_kit::audit::Record};

/// A router-profile change made in the Web UI, as the audit log records it.
pub(crate) enum ProfileAction<'profile> {
    /// A profile was added with its password.
    Create(&'profile ManagedRouterProfile),
    /// A profile was changed; `password` tells whether a new password was stored.
    Update {
        /// The profile after the change.
        profile: &'profile ManagedRouterProfile,
        /// Whether the stored password was replaced.
        password: bool,
    },
    /// A profile and its stored password were removed.
    Delete(&'profile ManagedRouterProfile),
}

impl ProfileAction<'_> {
    /// The audit action id, the changed profile and whether its credentials changed.
    const fn parts(&self) -> (&'static str, &ManagedRouterProfile, bool) {
        match *self {
            Self::Create(profile) => ("router.profile_create", profile, true),
            Self::Update { profile, password } => ("router.profile_update", profile, password),
            Self::Delete(profile) => ("router.profile_delete", profile, true),
        }
    }
}

/// Appends a router-profile audit event with no credential material.
// NOT cancel-safe: an abandoned append may still be written.
pub(crate) async fn audit(state: &WebState, user: &CurrentUser, change: ProfileAction<'_>) {
    let (action, profile, credentials_changed) = change.parts();
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
            "credentials_changed": credentials_changed,
        }))
        .append(state, user, "success")
        .await;
}
