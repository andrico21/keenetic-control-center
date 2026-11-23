//! Deleting a Web UI router profile: the confirmation dialog and the delete action.

use askama::Template;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse as _, Response},
};
use fluent_bundle::FluentArgs;
use kcc_app::{credentials::CredentialKind, entware_ssh, registry::ProfileSource};
use kcc_i18n::{bundle::tr, keys};

use crate::{
    WebState,
    authz::CurrentUser,
    errors,
    nav::Section,
    page::{Localize as _, Shell},
    page_kit::{
        context::{fragment_shell, managed},
        respond::open,
    },
    router_access::{ProfileAction, audit},
    system_pages::entware_ssh::store,
};

/// `GET /ui/routers/{id}/delete`: the confirmation dialog.
// cancel-safe: it only reads the router list.
pub(crate) async fn delete_dialog(
    State(state): State<WebState>,
    Path(id): Path<String>,
    user: CurrentUser,
) -> Response {
    let shell = fragment_shell(user.locale());
    let Some(fleet) = state.fleet() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    match managed(fleet, user.role(), &id).await {
        Ok(entry) if matches!(entry.source, ProfileSource::State) => {
            let ssh_active =
                store(&state).is_some_and(|records| entware_ssh::state::active(&records, &id));
            errors::render(&DeleteDialog::new(shell, id, ssh_active))
        }
        Ok(_) => StatusCode::FORBIDDEN.into_response(),
        Err(refusal) => refusal.page(shell),
    }
}

/// `POST /ui/routers/{id}/delete`: forgets a Web UI profile and its password file.
// NOT cancel-safe: the profile is removed from `routers.json` on a blocking thread that finishes
// even if the future is dropped, and the removal's audit entry may then be skipped or written late.
pub(crate) async fn delete(
    State(state): State<WebState>,
    Path(id): Path<String>,
    user: CurrentUser,
) -> Response {
    let shell = fragment_shell(user.locale());
    let Some(fleet) = state.fleet() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let entry = match managed(fleet, user.role(), &id).await {
        Ok(entry) if matches!(entry.source, ProfileSource::State) => entry,
        Ok(_) => return StatusCode::FORBIDDEN.into_response(),
        Err(refusal) => return refusal.page(shell),
    };
    if let Err(error) = fleet.registry().delete(user.role(), &id).await {
        return errors::internal(&error, shell);
    }
    if CredentialKind::ALL.into_iter().any(|kind| {
        entry
            .profile
            .credential_path(kind)
            .is_some_and(|path| matches!(fleet.credentials().manages(&id, kind, path), Ok(true)))
    }) && let Err(error) = fleet.credentials().remove(&id)
    {
        tracing::error!(router = %id, %error, "router credential could not be removed");
    }
    if let Err(error) = entware_ssh::state::forget(fleet.registry().state(), &id) {
        tracing::error!(router = %id, %error, "router SSH state could not be removed");
    }
    audit(&state, &user, ProfileAction::Delete(&entry.profile)).await;
    open(Section::Dashboard.href())
}

/// The delete confirmation shown in the shared dialog.
#[derive(Template)]
#[template(path = "partials/router_delete.html")]
pub(crate) struct DeleteDialog {
    /// Locale carrier.
    shell: Shell,
    /// The router to delete.
    id: String,
    /// Dialog title.
    title: String,
    /// Whether the router still authorizes kcc's Entware SSH key line.
    ssh_active: bool,
}

impl DeleteDialog {
    /// The confirmation for `id`; `ssh_active` when the router still authorizes kcc's
    /// Entware SSH key line, which the removal leaves there.
    pub(crate) fn new(shell: Shell, id: String, ssh_active: bool) -> Self {
        let mut args = FluentArgs::new();
        args.set("name", id.clone());
        let title = tr(shell.locale(), keys::WEB_ROUTER_DELETE_TITLE, Some(&args));
        Self {
            shell,
            id,
            title,
            ssh_active,
        }
    }
}

localized!(DeleteDialog);
