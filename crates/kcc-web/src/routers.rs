//! Router profile management: `/ui/routers/new` and `/ui/routers/{id}/edit`.
//!
//! The route table requires `ManageRouters` for every route here and the registry checks
//! the router scope again. Profiles from `kcc.toml` are read-only. Every typed secret (the
//! password, the token, the read-only password) moves into a `SecretString` and then into
//! its sealed record; it is never rendered, logged or audited. Every create, update and
//! delete is audited with the changed credential kinds only.

use std::path::PathBuf;

use axum::{
    Form,
    extract::{Path, State},
    http::HeaderMap,
    response::{IntoResponse as _, Redirect, Response},
};
use kcc_app::registry::{
    ManagedRouterProfile, ProfileSource, RegistryError,
    sealed_edit::{SealedEdit, update_sealed},
};
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
};

use crate::{
    WebState,
    authz::{CurrentSession, CurrentUser},
    errors::{self, Kind},
    fleet::Fleet,
    nav::Section,
    page_kit::{
        context::{Caller, lookup, managed},
        respond::{open, unprocessable},
    },
    router_access::{ProfileAction, audit},
    router_check::{allowed, policy_refusal},
    router_form::{
        Draft, FieldErrors, Parsed, RouterForm, Typed,
        address::is_slug,
        page::{FormPage, Stored},
        plan::{Plan, Refusal},
    },
};

/// `GET /ui/routers/new`: the add form.
pub(crate) async fn new_page(
    State(state): State<WebState>,
    headers: HeaderMap,
    current: CurrentSession,
    user: CurrentUser,
) -> Response {
    if state.fleet().is_none() {
        return Redirect::to(Section::Dashboard.href()).into_response();
    }
    let shell = Caller::new(&headers, &current, &user)
        .shell(&state, Section::Dashboard, None)
        .await;
    errors::render(&FormPage::add(
        shell,
        Draft::default(),
        FieldErrors::default(),
    ))
}

/// `POST /ui/routers/new`: validates, checks the outbound policy, stores the profile and
/// seals its credentials, and opens the new router's dashboard.
pub(crate) async fn create(
    State(state): State<WebState>,
    headers: HeaderMap,
    current: CurrentSession,
    user: CurrentUser,
    Form(form): Form<RouterForm>,
) -> Response {
    let Some(fleet) = state.fleet() else {
        return Redirect::to(Section::Dashboard.href()).into_response();
    };
    let shell = Caller::new(&headers, &current, &user)
        .shell(&state, Section::Dashboard, None)
        .await;
    let locale = user.locale();
    let (draft, typed, parsed) = form.parse(locale, true);
    let mut errors = parsed.as_ref().err().cloned().unwrap_or_default();
    if let Some(key) = id_refusal(fleet, &user, draft.id()).await {
        errors.set_id(tr(locale, key, None));
    }
    if let Ok(fields) = &parsed
        && !allowed(fleet, fields.url()).await
    {
        errors.set_url(policy_refusal(locale, fields.url()));
    }
    let planned = plan(None, &parsed, typed).unwrap_or_else(|refusal| {
        refusal.mark(&mut errors, locale);
        None
    });
    let (Ok(fields), Some(plan), false) = (parsed, planned, errors.any()) else {
        return unprocessable(&FormPage::add(shell, draft, errors));
    };
    let id = draft.id().to_owned();
    let store = fleet.credentials();
    let mut profile = ManagedRouterProfile::new(
        id.clone(),
        fields.url().clone(),
        String::new(),
        PathBuf::new(),
    );
    fields.apply(&mut profile);
    if let Err(error) = plan.point(store, &mut profile) {
        return errors::internal(&error, shell);
    }
    match fleet.registry().create(user.role(), profile.clone()).await {
        Ok(()) => {}
        Err(RegistryError::AlreadyExists { id: _ }) => {
            errors.set_id(tr(locale, keys::WEB_ROUTER_ERROR_EXISTS, None));
            return unprocessable(&FormPage::add(shell, draft, errors));
        }
        Err(RegistryError::PermissionDenied { router: _ }) => {
            return errors::response(Kind::Forbidden, shell);
        }
        Err(error) => return errors::internal(&error, shell),
    }
    if let Err(error) = plan.seal(store, &id) {
        if let Err(rollback) = fleet.registry().delete(user.role(), &id).await {
            tracing::error!(error = %rollback, "router profile rollback failed");
        }
        if let Err(cleanup) = store.remove(&id) {
            tracing::error!(router = %id, error = %cleanup, "router credential cleanup failed");
        }
        return errors::internal(&error, shell);
    }
    let credentials = plan.changed();
    let change = ProfileAction::Create {
        profile: &profile,
        credentials: &credentials,
    };
    audit(&state, &user, change).await;
    open(&format!("/ui/r/{id}"))
}

/// Why a new router cannot take the id `id`: not a slug, or already taken.
// cancel-safe: reads the registry only.
async fn id_refusal(fleet: &Fleet, user: &CurrentUser, id: &str) -> Option<MessageKey> {
    if !is_slug(id) {
        return Some(keys::WEB_ROUTER_ERROR_ID);
    }
    matches!(lookup(fleet, user.role(), id).await, Ok(Some(_)))
        .then_some(keys::WEB_ROUTER_ERROR_EXISTS)
}

/// Plans the credentials of a valid form for a new profile (`stored` is `None`) or the
/// edit of `stored`; `None` when the fields are invalid.
///
/// # Errors
///
/// Returns the fields a refused submit has to fill in.
fn plan(
    stored: Option<&ManagedRouterProfile>,
    parsed: &Result<Parsed, FieldErrors>,
    typed: Typed,
) -> Result<Option<Plan>, Refusal> {
    parsed
        .as_ref()
        .ok()
        .map(|fields| Plan::new(stored, fields, typed))
        .transpose()
}

/// `GET /ui/routers/{id}/edit`: the edit form, or the read-only view of a `kcc.toml`
/// profile.
pub(crate) async fn edit_page(
    State(state): State<WebState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    current: CurrentSession,
    user: CurrentUser,
) -> Response {
    let Some(fleet) = state.fleet() else {
        return Redirect::to(Section::Dashboard.href()).into_response();
    };
    let shell = Caller::new(&headers, &current, &user)
        .shell(&state, Section::Dashboard, None)
        .await;
    let entry = match managed(fleet, user.role(), &id).await {
        Ok(entry) => entry,
        Err(refusal) => return refusal.page(shell),
    };
    let draft = Draft::from_profile(&entry.profile);
    let page = FormPage::edit(shell, draft, FieldErrors::default())
        .with_stored(Stored::of(fleet.credentials(), &entry.profile));
    match entry.source {
        ProfileSource::Config => errors::render(&page.read_only()),
        ProfileSource::State | _ => errors::render(&page),
    }
}

/// `POST /ui/routers/{id}/edit`: updates a Web UI profile.
///
/// An empty secret field keeps the stored secret unless the address, login or TLS mode
/// moves or the sign-in mode switches between password and token ([`Plan`]); a move also
/// drops the read-only login and its sealed record unless they are entered again. A
/// failed update puts the previous sealed records back.
pub(crate) async fn update(
    State(state): State<WebState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    current: CurrentSession,
    user: CurrentUser,
    Form(form): Form<RouterForm>,
) -> Response {
    let Some(fleet) = state.fleet() else {
        return Redirect::to(Section::Dashboard.href()).into_response();
    };
    let shell = Caller::new(&headers, &current, &user)
        .shell(&state, Section::Dashboard, None)
        .await;
    let entry = match managed(fleet, user.role(), &id).await {
        Ok(entry) if matches!(entry.source, ProfileSource::State) => entry,
        Ok(_) => return errors::response(Kind::Forbidden, shell),
        Err(refusal) => return refusal.page(shell),
    };
    let locale = user.locale();
    let (submitted, typed, parsed) = form.parse(locale, false);
    let draft = submitted.with_id(id.clone());
    let mut errors = parsed.as_ref().err().cloned().unwrap_or_default();
    if let Ok(fields) = &parsed
        && !allowed(fleet, fields.url()).await
    {
        errors.set_url(policy_refusal(locale, fields.url()));
    }
    let store = fleet.credentials();
    let stored = entry.profile;
    let planned = plan(Some(&stored), &parsed, typed).unwrap_or_else(|refusal| {
        refusal.mark(&mut errors, locale);
        None
    });
    let (Ok(fields), Some(plan), false) = (parsed, planned, errors.any()) else {
        let page = FormPage::edit(shell, draft, errors).with_stored(Stored::of(store, &stored));
        return unprocessable(&page);
    };
    let mut profile = stored;
    fields.apply(&mut profile);
    if let Err(error) = plan.point(store, &mut profile) {
        return errors::internal(&error, shell);
    }
    let edit = SealedEdit::new(profile.clone(), plan.secrets());
    match update_sealed(fleet.registry(), store, user.role(), edit).await {
        Ok(()) => {}
        Err(RegistryError::PermissionDenied { router: _ }) => {
            return errors::response(Kind::Forbidden, shell);
        }
        Err(error) => return errors::internal(&error, shell),
    }
    if let Err(error) = plan.remove(store, &id) {
        tracing::error!(router = %id, %error, "router credential could not be removed");
    }
    let credentials = plan.changed();
    let change = ProfileAction::Update {
        profile: &profile,
        credentials: &credentials,
    };
    audit(&state, &user, change).await;
    open(&format!("/ui/r/{id}"))
}
