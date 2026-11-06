//! Access, audit and redirect helpers shared by the router management routes.

use core::error::Error;

use axum::{
    http::{HeaderValue, StatusCode},
    response::{IntoResponse as _, Response},
};
use kcc_app::{
    audit::{Actor, ActorKind, AuditEvent},
    permissions::{Permission, Role},
    registry::{self, ManagedRouterProfile, RegistryEntry},
    settings::RouterTls,
};
use serde_json::json;

use crate::{
    WebState, auth,
    authz::CurrentUser,
    errors::{self, Kind},
    fleet::Fleet,
    page::Shell,
};

/// The visible profile `id`, if any.
///
/// # Errors
///
/// Returns registry read failures.
// cancel-safe: reads only.
pub(crate) async fn lookup(
    fleet: &Fleet,
    role: &Role,
    id: &str,
) -> Result<Option<RegistryEntry>, Box<dyn Error + Send + Sync>> {
    Ok(fleet
        .visible(role)
        .await?
        .into_iter()
        .find(|entry| entry.profile.id == id))
}

/// Why a profile cannot be managed.
pub(crate) enum Refusal {
    /// The role lacks `ManageRouters` for the router.
    Forbidden,
    /// No visible profile has the id.
    Missing,
    /// The registry could not be read.
    Failed(Box<dyn Error + Send + Sync>),
}

impl Refusal {
    /// The error page for this refusal.
    pub(crate) fn respond(self, shell: Shell) -> Response {
        match self {
            Self::Forbidden => errors::response(Kind::Forbidden, shell),
            Self::Missing => errors::response(Kind::NotFound, shell),
            Self::Failed(error) => errors::internal(&error, shell),
        }
    }
}

/// The profile `id` when `role` may manage it.
///
/// # Errors
///
/// Returns the refusal to answer with.
// cancel-safe: reads only.
pub(crate) async fn managed(
    fleet: &Fleet,
    role: &Role,
    id: &str,
) -> Result<RegistryEntry, Refusal> {
    if registry::authorize(role, Permission::ManageRouters, id).is_err() {
        return Err(Refusal::Forbidden);
    }
    match lookup(fleet, role, id).await {
        Ok(Some(entry)) => Ok(entry),
        Ok(None) => Err(Refusal::Missing),
        Err(error) => Err(Refusal::Failed(error)),
    }
}

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
    let event = AuditEvent::new(
        state.unix_seconds(),
        Actor::new(ActorKind::Web, user.username().to_owned()),
        action.to_owned(),
    )
    .with_router(profile.id.clone())
    .with_target(profile.id.clone())
    .with_params(json!({
        "url": profile.url.as_str(),
        "login": profile.login,
        "tls": tls,
        "tags": profile.tags,
        "test_device": profile.test_device,
        "credentials_changed": credentials_changed,
    }))
    .with_result("success".to_owned(), auth::request_id());
    if let Err(error) = state.audit().append(event).await {
        tracing::error!(%error, action, "router profile audit failed");
    }
}

/// Answers an htmx form post by sending the browser to `href`.
pub(crate) fn open(href: &str) -> Response {
    let mut response = StatusCode::OK.into_response();
    match HeaderValue::from_str(href) {
        Ok(value) => drop(response.headers_mut().insert("hx-redirect", value)),
        Err(error) => tracing::error!(%error, "redirect target is not a header value"),
    }
    response
}
