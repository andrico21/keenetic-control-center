//! One preset at `/ui/presets/{id}` (route table: `Read`): where it came from, and its
//! settings per group, redacted; Apply and Delete with `Migrate` on its source router,
//! Reveal secrets with `RevealSecrets` too.

use askama::Template;
use axum::{
    extract::{Path, State},
    http::HeaderMap,
    response::Response,
};
use kcc_app::permissions::Permission;
use kcc_i18n::keys;

use super::{
    lines::{by_group, count, group_title},
    list::{may_change, source_text},
    saved,
};
use crate::{
    WebState,
    admin_shared::Timestamp,
    authz::{CurrentSession, CurrentUser},
    errors::{self, Kind},
    nav::Section,
    page::{Localize as _, Shell},
    page_kit::context::{Caller, Refusal},
    wizard::services::Services,
};

/// The preset page.
#[derive(Template)]
#[template(path = "pages/presets_detail.html")]
struct Detail {
    /// Page shell.
    shell: Shell,
    /// Preset id.
    id: String,
    /// Its name.
    name: String,
    /// Its description.
    description: String,
    /// Where it came from.
    source: String,
    /// When it was captured.
    captured: Option<Timestamp>,
    /// Who captured it.
    creator: String,
    /// Its groups: id, name, count and redacted lines.
    groups: Vec<Group>,
    /// Whether the role may apply and delete it.
    may_change: bool,
    /// Whether the role may reveal its secret values.
    may_reveal: bool,
}

localized!(Detail);

/// One group of the preset.
struct Group {
    /// Group id.
    id: String,
    /// Its name.
    title: String,
    /// "3 settings".
    count: String,
    /// Its settings, redacted.
    lines: Vec<String>,
}

/// `GET /ui/presets/{id}`: the preset, redacted.
// cancel-safe: reads only.
pub(super) async fn page(
    State(state): State<WebState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    current: CurrentSession,
    user: CurrentUser,
) -> Response {
    let shell = Caller::new(&headers, &current, &user)
        .shell(&state, Section::Presets, None)
        .await;
    let services = match Services::of(&state, &user) {
        Ok(found) => found,
        Err(refusal) => return refusal.page(shell),
    };
    let presets = match saved::list(services.fleet(), user.role()).await {
        Ok(found) => found,
        Err(error) => return Refusal::Failed(Box::new(error)).page(shell),
    };
    let Some(preset) = presets.into_iter().find(|preset| preset.id == id) else {
        return errors::response(Kind::NotFound, shell);
    };
    let locale = user.locale();
    let may_change = may_change(services, &preset);
    let groups = by_group(&preset)
        .into_iter()
        .map(|(group, lines)| Group {
            title: group_title(&group, locale),
            count: count(locale, lines.len()),
            id: group,
            lines,
        })
        .collect();
    errors::render(&Detail {
        id: preset.id.clone(),
        name: preset.name.clone(),
        description: preset.description.clone(),
        source: source_text(&preset, locale),
        captured: Timestamp::at(preset.source.captured_at, locale),
        creator: preset.created_by.clone(),
        groups,
        may_change,
        may_reveal: may_change && user.role().grants(Permission::RevealSecrets),
        shell,
    })
}
