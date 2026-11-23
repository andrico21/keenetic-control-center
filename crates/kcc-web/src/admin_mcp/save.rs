//! `POST /ui/admin/mcp` and `POST /ui/admin/mcp/reset`: a section's changed values, or a
//! value set on the Web removed so kcc.toml applies again, planned as the signed-in role.

extern crate alloc;

use alloc::sync::Arc;
use core::str::FromStr as _;

use axum::{Form, extract::State, http::StatusCode, response::Response};
use kcc_app::{
    mcp_settings::{Candidate, SettingsError, document::McpOverrides, keys::KeyPath},
    settings::mcp_schema::OauthMode,
};
use kcc_i18n::keys;
use tokio::task::{JoinError, spawn_blocking};

use super::{
    Attached, Posted,
    flow::submit,
    form::{FormError, Submitted},
    messages::Said,
    reply,
};
use crate::{
    WebState, admin::issuer::Issuer, admin_shared::unavailable, authz::CurrentUser, errors,
    page_kit::context::fragment_shell,
};

/// Where a section's change posts.
const SAVE: &str = "/ui/admin/mcp";

/// Where a reset posts.
const RESET: &str = "/ui/admin/mcp/reset";

/// `POST /ui/admin/mcp`: the edited keys whose values differ from the effective ones.
// NOT cancel-safe: dropped after the hand-over, the change runs on unaudited.
pub(crate) async fn save(
    State(state): State<WebState>,
    user: CurrentUser,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Response {
    let (Some(admin), Some(attached)) = (state.admin(), state.mcp().map(Arc::clone)) else {
        return unavailable(None);
    };
    let locale = user.locale();
    let submitted = match Submitted::parse(&pairs) {
        Ok(submitted) => submitted,
        Err(error) => return form_refused(&user, error),
    };
    let _changes = admin.lock().await;
    let (store, base) = (admin.state().clone(), admin.mcp().clone());
    let effective = match spawn_blocking(move || base.effective(&store)).await {
        Ok(Ok(effective)) => effective,
        Ok(Err(error)) => return plan_refused(&user, &error),
        Err(error) => return errors::internal(&error, fragment_shell(locale)),
    };
    let change = match submitted.change(&effective) {
        Ok(change) => change,
        Err(error) => return form_refused(&user, error),
    };
    if change == McpOverrides::default() {
        let said = Said::new(locale, keys::WEB_ADMIN_MCP_UNCHANGED, None);
        return reply::notice(&state, &user, (said, "info"), StatusCode::OK).await;
    }
    let known = attached.control().toolsets();
    let (mcp_base, directory, actor) = (
        admin.mcp().clone(),
        admin.state().clone(),
        user.role().clone(),
    );
    let planned = spawn_blocking(move || {
        let toolsets = |name: &str| {
            known
                .iter()
                .find(|toolset| toolset.name == name)
                .map(|toolset| toolset.safety_reducing)
        };
        mcp_base.plan_update(&directory, &actor, &change, &toolsets)
    })
    .await;
    let posted = Posted {
        to: SAVE,
        pairs: &pairs,
        password: submitted.password(),
        revision: submitted.revision(),
    };
    handed(&state, &user, (attached, planned), posted).await
}

/// `POST /ui/admin/mcp/reset`: removes the key named `key` from `mcp_settings.json`.
// NOT cancel-safe: dropped after the hand-over, the change runs on unaudited.
pub(crate) async fn reset(
    State(state): State<WebState>,
    user: CurrentUser,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Response {
    let (Some(admin), Some(attached)) = (state.admin(), state.mcp().map(Arc::clone)) else {
        return unavailable(None);
    };
    let submitted = match Submitted::parse(&pairs) {
        Ok(submitted) => submitted,
        Err(error) => return form_refused(&user, error),
    };
    let Some(key) = submitted
        .value("key")
        .and_then(|name| KeyPath::from_str(name).ok())
    else {
        return form_refused(&user, FormError::UnknownField);
    };
    let _changes = admin.lock().await;
    let (store, base, actor) = (
        admin.state().clone(),
        admin.mcp().clone(),
        user.role().clone(),
    );
    let planned = spawn_blocking(move || base.reset(&store, &actor, key)).await;
    let posted = Posted {
        to: RESET,
        pairs: &pairs,
        password: submitted.password(),
        revision: submitted.revision(),
    };
    handed(&state, &user, (attached, planned), posted).await
}

/// Submits a planned change, or answers why it could not be planned.
///
/// A change from a form rendered on another settings revision is refused like one the
/// settings changed under: the page is stale and must be read again.
// NOT cancel-safe: dropped after the hand-over, the change runs on unaudited.
async fn handed(
    state: &WebState,
    user: &CurrentUser,
    (attached, planned): (
        Arc<Attached>,
        Result<Result<Candidate, SettingsError>, JoinError>,
    ),
    posted: Posted<'_>,
) -> Response {
    match planned {
        Ok(Ok(candidate))
            if posted
                .revision
                .is_some_and(|revision| revision != candidate.base_version()) =>
        {
            plan_refused(user, &SettingsError::SettingsChanged)
        }
        Ok(Ok(candidate)) if kcc_without_issuer(state, &candidate) => {
            let locale = user.locale();
            let said = Said::new(locale, keys::WEB_OAUTH_ISSUER_UNAVAILABLE, None);
            reply::refused(locale, said, StatusCode::UNPROCESSABLE_ENTITY)
        }
        Ok(Ok(candidate)) => submit(state, user, (attached, candidate), posted).await,
        Ok(Err(error)) => plan_refused(user, &error),
        Err(error) => errors::internal(&error, fragment_shell(user.locale())),
    }
}

/// A form that names a field the settings do not have or a value they cannot use.
fn form_refused(user: &CurrentUser, error: FormError) -> Response {
    let locale = user.locale();
    reply::refused(
        locale,
        Said::form(locale, error),
        StatusCode::UNPROCESSABLE_ENTITY,
    )
}

/// A change the settings refused, or the error page for a state failure.
fn plan_refused(user: &CurrentUser, error: &SettingsError) -> Response {
    let locale = user.locale();
    let status = if matches!(
        error,
        SettingsError::SettingsChanged | SettingsError::RevisionExhausted
    ) {
        StatusCode::CONFLICT
    } else {
        StatusCode::UNPROCESSABLE_ENTITY
    };
    Said::plan(locale, error).map_or_else(
        || errors::internal(error, fragment_shell(locale)),
        |said| reply::refused(locale, said, status),
    )
}

/// Whether `candidate` turns kcc sign-in on for a listener while kcc's authorization server
/// has no issuer (no DNS public URL and no loopback main listener, or no Web UI).
fn kcc_without_issuer(state: &WebState, candidate: &Candidate) -> bool {
    let issuer_missing = state
        .admin()
        .is_some_and(|admin| !matches!(admin.server().issuer(), Issuer::Url(_)));
    let auth = &candidate.effective().settings().auth;
    let turned_on = |key: KeyPath, mode: OauthMode| {
        mode == OauthMode::Kcc && candidate.changed().contains(&key)
    };
    issuer_missing
        && (turned_on(KeyPath::MainOauth, auth.main.oauth)
            || turned_on(KeyPath::DedicatedOauth, auth.dedicated.oauth))
}
