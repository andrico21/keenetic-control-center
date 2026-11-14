//! The presets at `/ui/presets` (route table: `Read`): every preset whose source router
//! the role may read, with Apply and Delete where it may migrate with that router.

use askama::Template;
use axum::{extract::State, http::HeaderMap, response::Response};
use fluent_bundle::FluentArgs;
use kcc_app::permissions::Permission;
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_migrate::presets::model::{Preset, PresetSourceKind};

use super::{lines::group_title, saved};
use crate::{
    WebState,
    admin_shared::Timestamp,
    authz::{CurrentSession, CurrentUser},
    errors,
    nav::Section,
    page::{Localize as _, Shell},
    page_kit::context::{Caller, Refusal},
    wizard::services::Services,
};

/// The presets page.
#[derive(Template)]
#[template(path = "pages/presets_list.html")]
struct List {
    /// Page shell.
    shell: Shell,
    /// Whether the role may capture and copy (`Migrate`).
    may_create: bool,
    /// The presets, by name.
    rows: Vec<Row>,
}

localized!(List);

/// One preset of the list.
struct Row {
    /// Preset id.
    id: String,
    /// Its name.
    name: String,
    /// Its groups' names.
    groups: String,
    /// Where it came from.
    source: String,
    /// When it was captured.
    captured: Option<Timestamp>,
    /// Who captured it.
    creator: String,
    /// Whether the role may apply and delete it.
    may_change: bool,
}

/// `GET /ui/presets`: the list.
// cancel-safe: reads only.
pub(super) async fn page(
    State(state): State<WebState>,
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
    let presets = match saved::store(services.fleet()).list(user.role()) {
        Ok(found) => found,
        Err(error) => return Refusal::Failed(Box::new(error)).page(shell),
    };
    let locale = user.locale();
    let mut rows = presets
        .iter()
        .map(|preset| Row {
            id: preset.id.clone(),
            name: preset.name.clone(),
            groups: preset
                .groups
                .iter()
                .map(|group| group_title(group, locale))
                .collect::<Vec<_>>()
                .join(", "),
            source: source_text(preset, locale),
            captured: Timestamp::at(preset.source.captured_at),
            creator: preset.created_by.clone(),
            may_change: may_change(services, preset),
        })
        .collect::<Vec<_>>();
    rows.sort_by(|left, right| left.name.cmp(&right.name).then(left.id.cmp(&right.id)));
    errors::render(&List {
        shell,
        may_create: user.role().grants(Permission::Migrate),
        rows,
    })
}

/// Whether the user of `services` may apply and delete `preset`: `Migrate`, on its
/// source router when it has one.
pub(super) fn may_change(services: Services<'_>, preset: &Preset) -> bool {
    services.user().role().grants(Permission::Migrate)
        && preset
            .source
            .router_id
            .as_deref()
            .is_none_or(|router| services.may_migrate(router))
}

/// Where `preset` came from: model, firmware and router, backup or file.
pub(super) fn source_text(preset: &Preset, locale: Locale) -> String {
    let source = &preset.source;
    let mut args = FluentArgs::new();
    args.set("model", source.model.clone());
    args.set("version", source.firmware_version.clone());
    args.set("router", source.router_id.clone().unwrap_or_default());
    let key = match source.kind {
        PresetSourceKind::Router => keys::WEB_PRESETS_SOURCE_ROUTER,
        PresetSourceKind::Backup => keys::WEB_PRESETS_SOURCE_BACKUP,
        PresetSourceKind::File | _ => keys::WEB_PRESETS_SOURCE_FILE,
    };
    tr(locale, key, Some(&args))
}
