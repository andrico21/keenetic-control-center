//! Router profile management: `/ui/routers/new` and `/ui/routers/{id}/edit`.
//!
//! The route table requires `ManageRouters` for every route here and the registry checks
//! the router scope again. Profiles from `kcc.toml` are read-only. A typed password moves
//! into a `SecretString` and then into an owner-only file; it is never rendered, logged
//! or audited. Every create, update and delete is audited without credentials.
//!
//! The route table requires `ManageRouters` for every route here and the registry checks
//! the router scope again. Profiles from `kcc.toml` are read-only. A typed password moves
//! into a [`SecretString`] and then into an owner-only file; it is never rendered, logged
//! or audited. Every create, update and delete is audited without credentials.

use axum::{
    Form,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse as _, Redirect, Response},
};
use kcc_app::registry::{ManagedRouterProfile, ProfileSource, RegistryError};
use kcc_i18n::{bundle::tr, keys};

use crate::{
    WebState,
    authz::{CurrentSession, CurrentUser},
    credentials,
    errors::{self, Kind},
    nav::Section,
    overview::masthead,
    page::Shell,
    prefs,
    router_access::{ProfileAction, audit, lookup, managed, open},
    router_check::allowed,
    router_form::{Draft, FieldErrors, FormPage, RouterForm, is_slug},
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
    let shell = shell(&state, &headers, &current, &user).await;
    errors::render(&FormPage::add(
        shell,
        Draft::default(),
        FieldErrors::default(),
    ))
}

/// `POST /ui/routers/new`: validates, checks the outbound policy, stores the profile and
/// its password file, and opens the new router's dashboard.
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
    let shell = shell(&state, &headers, &current, &user).await;
    let locale = user.locale();
    let (draft, password, parsed) = form.parse(locale, true);
    let mut errors = parsed.as_ref().err().cloned().unwrap_or_default();
    let slug = is_slug(draft.id());
    let taken = slug && matches!(lookup(fleet, user.role(), draft.id()).await, Ok(Some(_)));
    match (slug, taken) {
        (false, _) => errors.set_id(tr(locale, keys::WEB_ROUTER_ERROR_ID, None)),
        (true, true) => errors.set_id(tr(locale, keys::WEB_ROUTER_ERROR_EXISTS, None)),
        (true, false) => {}
    }
    if let Ok(fields) = &parsed
        && !allowed(fleet, fields.url()).await
    {
        errors.set_url(tr(locale, keys::WEB_ROUTER_ERROR_POLICY, None));
    }
    let (Ok(fields), Some(secret), false) = (parsed, password, errors.any()) else {
        return invalid(&FormPage::add(shell, draft, errors));
    };
    let id = draft.id().to_owned();
    let file = credentials::path(fleet.credentials_dir(), &id);
    let mut profile = ManagedRouterProfile::new(
        id.clone(),
        fields.url().clone(),
        String::new(),
        file.clone(),
    );
    fields.apply(&mut profile);
    match fleet.registry().create(user.role(), profile.clone()).await {
        Ok(()) => {}
        Err(RegistryError::AlreadyExists { id: _ }) => {
            errors.set_id(tr(locale, keys::WEB_ROUTER_ERROR_EXISTS, None));
            return invalid(&FormPage::add(shell, draft, errors));
        }
        Err(RegistryError::PermissionDenied { router: _ }) => {
            return errors::response(Kind::Forbidden, shell);
        }
        Err(error) => return errors::internal(&error, shell),
    }
    let directory = fleet.credentials_dir().to_owned();
    if let Err(error) = credentials::store(directory, file, secret).await {
        if let Err(rollback) = fleet.registry().delete(user.role(), &id).await {
            tracing::error!(error = %rollback, "router profile rollback failed");
        }
        return errors::internal(&error, shell);
    }
    audit(&state, &user, ProfileAction::Create(&profile)).await;
    open(&format!("/ui/r/{id}"))
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
    let shell = shell(&state, &headers, &current, &user).await;
    let entry = match managed(fleet, user.role(), &id).await {
        Ok(entry) => entry,
        Err(refusal) => return refusal.respond(shell),
    };
    let page = FormPage::edit(
        shell,
        Draft::from_profile(&entry.profile),
        FieldErrors::default(),
    );
    match entry.source {
        ProfileSource::Config => errors::render(&page.read_only()),
        ProfileSource::State | _ => errors::render(&page),
    }
}

/// `POST /ui/routers/{id}/edit`: updates a Web UI profile; an empty password keeps the
/// stored one.
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
    let shell = shell(&state, &headers, &current, &user).await;
    let entry = match managed(fleet, user.role(), &id).await {
        Ok(entry) if matches!(entry.source, ProfileSource::State) => entry,
        Ok(_) => return errors::response(Kind::Forbidden, shell),
        Err(refusal) => return refusal.respond(shell),
    };
    let locale = user.locale();
    let (submitted, password, parsed) = form.parse(locale, false);
    let draft = submitted.with_id(id.clone());
    let mut errors = parsed.as_ref().err().cloned().unwrap_or_default();
    if let Ok(fields) = &parsed
        && !allowed(fleet, fields.url()).await
    {
        errors.set_url(tr(locale, keys::WEB_ROUTER_ERROR_POLICY, None));
    }
    let (Ok(fields), false) = (parsed, errors.any()) else {
        return invalid(&FormPage::edit(shell, draft, errors));
    };
    let mut profile = entry.profile;
    fields.apply(&mut profile);
    let changed = password.is_some();
    if let Some(secret) = password {
        let file = credentials::path(fleet.credentials_dir(), &id);
        let directory = fleet.credentials_dir().to_owned();
        if let Err(error) = credentials::store(directory, file.clone(), secret).await {
            return errors::internal(&error, shell);
        }
        profile.password_file = file;
    }
    match fleet.registry().update(user.role(), profile.clone()).await {
        Ok(()) => {}
        Err(RegistryError::PermissionDenied { router: _ }) => {
            return errors::response(Kind::Forbidden, shell);
        }
        Err(error) => return errors::internal(&error, shell),
    }
    let change = ProfileAction::Update {
        profile: &profile,
        password: changed,
    };
    audit(&state, &user, change).await;
    open(&format!("/ui/r/{id}"))
}

/// The page shell of the router forms, with the fleet switcher.
async fn shell(
    state: &WebState,
    headers: &HeaderMap,
    current: &CurrentSession,
    user: &CurrentUser,
) -> Shell {
    prefs::shell_for_locale(headers, user.locale())
        .with_csrf_token(current.session().csrf_token().to_owned())
        .with_section(Section::Dashboard)
        .with_fleet(masthead(state, user.role(), None).await, None)
}

/// The form page again with its field errors, as `422`.
fn invalid(page: &FormPage) -> Response {
    let mut response = errors::render(page);
    *response.status_mut() = StatusCode::UNPROCESSABLE_ENTITY;
    response
}
