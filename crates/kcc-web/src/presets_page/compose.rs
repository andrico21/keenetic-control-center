//! A new preset's groups at `/ui/presets/new/{draft}`: the page, the captured settings
//! as the choice changes, and Save (the panel is `compose_panel`).

use alloc::sync::Arc;

use askama::Template;
use axum::{
    Extension, Form,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse as _, Response},
};
use kcc_app::permissions::Permission;
use kcc_i18n::keys;
use kcc_migrate::presets::{model::CaptureRequest, store::PresetError};
use serde_json::json;

use super::{
    compose_panel::{Panel, Submitted, captured, source_ast},
    drafts::Drafts,
    saved,
};
use crate::{
    WebState,
    authz::{CurrentSession, CurrentUser},
    errors::{self, Kind},
    nav::Section,
    page::{Localize as _, Shell},
    page_kit::{
        audit::Record as Audit,
        context::{Caller, Refusal, fragment_shell},
        respond::{self, Answer},
    },
    wizard::ids::fresh_id,
};

/// The page around the panel.
#[derive(Template)]
#[template(path = "pages/presets_new.html")]
struct Page {
    /// Page shell.
    shell: Shell,
    /// The rendered panel.
    panel: String,
}

localized!(Page);

/// `GET /ui/presets/new/{draft}`: the groups of a read source.
// cancel-safe: reads only.
pub(super) async fn page(
    State(state): State<WebState>,
    Path(id): Path<String>,
    Extension(drafts): Extension<Arc<Drafts>>,
    headers: HeaderMap,
    current: CurrentSession,
    user: CurrentUser,
) -> Response {
    let shell = Caller::new(&headers, &current, &user)
        .shell(&state, Section::Presets, None)
        .await;
    if !user.role().grants(Permission::Migrate) {
        return errors::response(Kind::Forbidden, shell);
    }
    let draft = drafts.get(&id, user.username(), state.unix_seconds());
    let panel = Panel::new(user.locale(), &id, draft.as_deref(), None);
    match panel.render() {
        Ok(html) => errors::render(&Page { shell, panel: html }),
        Err(error) => errors::internal(&error, shell),
    }
}

/// `POST /ui/presets/new/{draft}/preview`: the captured settings of the chosen groups.
///
/// # Errors
///
/// Answers 403 without `Migrate` and 404 when the draft is gone.
// cancel-safe: reads only.
pub(super) async fn preview(
    State(state): State<WebState>,
    Path(id): Path<String>,
    Extension(drafts): Extension<Arc<Drafts>>,
    user: CurrentUser,
    Form(form): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    if !user.role().grants(Permission::Migrate) {
        return Err(Refusal::Forbidden.status().into());
    }
    let draft = drafts
        .get(&id, user.username(), state.unix_seconds())
        .ok_or_else(|| Answer::from(StatusCode::NOT_FOUND.into_response()))?;
    let chosen = Submitted::of(&form);
    Ok(errors::render(&captured(
        user.locale(),
        &draft,
        chosen.groups(),
    )))
}

/// `POST /ui/presets/new/{draft}`: saves the preset and opens it.
///
/// # Errors
///
/// Answers the audited 403 without `Migrate` on the source, and the panel with its
/// errors (422).
// NOT cancel-safe: the preset is stored before the audit append.
pub(super) async fn save(
    State(state): State<WebState>,
    Path(draft_id): Path<String>,
    Extension(drafts): Extension<Arc<Drafts>>,
    user: CurrentUser,
    Form(form): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let fleet = state.fleet().ok_or_else(|| Refusal::Unavailable.status())?;
    let locale = user.locale();
    let now = state.unix_seconds();
    let submitted = Submitted::of(&form);
    let draft = drafts.get(&draft_id, user.username(), now);
    let Some(found) = draft.as_deref() else {
        let panel = Panel::new(locale, &draft_id, None, Some(&submitted));
        return Err(respond::unprocessable(&panel).into());
    };
    let refused = Panel::new(locale, &draft_id, Some(found), Some(&submitted));
    if refused.refusing() {
        return Err(respond::unprocessable(&refused).into());
    }
    let id = fresh_id(now).ok_or_else(|| {
        Answer::from(errors::internal(
            "the random generator failed",
            fragment_shell(locale),
        ))
    })?;
    let source = found.preset_source();
    let audit = source.router_id.as_deref().map_or_else(
        || Audit::new("web.preset_capture", id.clone()),
        |router| Audit::on_router("web.preset_capture", router, id.clone()),
    );
    let (groups, name, description) = submitted.into_parts();
    let request = CaptureRequest::new(
        id.clone(),
        name,
        description,
        groups,
        source,
        user.username().to_owned(),
    );
    let ast = source_ast(found).unwrap_or_default();
    match saved::store(fleet).capture(user.role(), &ast, request) {
        Ok(preset) => {
            drafts.remove(&draft_id);
            audit
                .with_params(json!({ "groups": preset.groups, "settings": preset.lines.len() }))
                .append(&state, &user, "saved")
                .await;
            Ok(respond::open(&format!("/ui/presets/{id}")))
        }
        Err(PresetError::Forbidden) => {
            audit.append(&state, &user, "forbidden").await;
            Err(errors::response(Kind::Forbidden, fragment_shell(locale)).into())
        }
        Err(error) => Err(errors::internal(&error, fragment_shell(locale)).into()),
    }
}
