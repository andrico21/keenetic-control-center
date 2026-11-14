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
    table::{
        acts::Act,
        cells::{Cell, Layout},
        head::Head,
        piece::Piece,
        view::TableView,
    },
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
    table: TableView,
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
        table: presets_table(rows, locale),
    })
}

/// The table of the presets `rows` in `locale`, with Apply and Delete where the role may;
/// a note in its place when there is none.
fn presets_table(rows: Vec<Row>, locale: Locale) -> TableView {
    let mut view = TableView::new("table").wrapped("table-wrap presets-table");
    if rows.is_empty() {
        return view.blank("table-empty", tr(locale, keys::WEB_PRESETS_EMPTY, None));
    }
    for key in [
        keys::WEB_PRESETS_COL_NAME,
        keys::WEB_PRESETS_COL_GROUPS,
        keys::WEB_PRESETS_COL_SOURCE,
        keys::WEB_PRESETS_COL_CAPTURED,
        keys::WEB_PRESETS_COL_CREATOR,
    ] {
        view = view.head(Head::plain(tr(locale, key, None)));
    }
    view = view.head(Head::hidden(tr(
        locale,
        keys::WEB_PRESETS_COL_ACTIONS,
        None,
    )));
    for row in rows {
        let id = format!("preset-{}", row.id);
        let page = format!("/ui/presets/{}", row.id);
        let mut acts = Vec::new();
        if row.may_change {
            acts.push(Act::link(
                locale,
                keys::WEB_PRESETS_APPLY,
                format!("{page}/apply"),
            ));
            let delete = Act::open(locale, keys::WEB_PRESETS_DELETE, format!("{page}/delete"));
            acts.push(delete.danger());
        }
        let captured = row
            .captured
            .map(|time| Piece::time(time.iso().to_owned(), time.text().to_owned()));
        view = view.row(vec![
            Cell::of(vec![Piece::link(page, row.name)])
                .attr("id", id.clone())
                .head(),
            Cell::text(row.groups),
            Cell::text(row.source),
            Cell::of(captured.into_iter().collect()),
            Cell::text(row.creator),
            Cell::acts(Layout::Block, acts, id).class("presets-table__actions"),
        ]);
    }
    view
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
