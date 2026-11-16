//! The run pages of `/ui/copy` (copy settings once) and `/ui/presets/{id}/apply` (apply
//! a preset): the user's runs and Start, which creates a run and opens its first step.

use alloc::sync::Arc;

use askama::Template;
use axum::{
    Extension,
    extract::{Path, State},
    http::HeaderMap,
    response::Response,
};
use fluent_bundle::FluentArgs;
use kcc_app::permissions::Permission;
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use serde_json::json;

use super::{record::Record, saved, steps::Origin, summary};
use crate::{
    WebState,
    admin_shared::Timestamp,
    authz::{CurrentSession, CurrentUser},
    errors::{self, Kind},
    nav::Section,
    page::{Localize as _, Shell},
    page_kit::{
        audit::Record as Audit,
        context::{Caller, Refusal, fragment_shell},
        respond::Answer,
    },
    table::{cells::Cell, view::TableView},
    wizard::{
        flow::{Flow as _, Stage as _},
        ids::fresh_id,
        retention,
        runs::{runs_table, started},
        screen,
        service::Wizards,
        services::Services,
        store::Store,
    },
};

/// A run page.
#[derive(Template)]
#[template(path = "pages/presets_runs.html")]
struct Landing {
    /// Page shell.
    shell: Shell,
    /// The page title.
    title: String,
    /// The sentence under it.
    intro: String,
    /// Where Start posts.
    start: String,
    /// Start's label.
    start_label: String,
    /// The user's runs, newest first.
    table: TableView,
}

localized!(Landing);

/// `GET /ui/copy`: the user's runs and Start copying.
// cancel-safe: every change comes after the last await.
pub(super) async fn copy_page(
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
    if !user.role().grants(Permission::Migrate) {
        return errors::response(Kind::Forbidden, shell);
    }
    saved::sweep(services, state.unix_seconds());
    let locale = user.locale();
    let rows = runs(&services.store(), user.username(), |_record| true);
    errors::render(&Landing {
        title: tr(locale, keys::WEB_PRESETS_COPY, None),
        intro: tr(locale, keys::WEB_PRESETS_COPY_INTRO, None),
        start: "/ui/copy".to_owned(),
        start_label: tr(locale, keys::WEB_PRESETS_COPY_START, None),
        table: runs_view(&rows, locale),
        shell,
    })
}

/// `GET /ui/presets/{id}/apply`: the user's runs of the preset and Start applying.
// cancel-safe: every change comes after the last await.
pub(super) async fn preset_page(
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
    let (name, _source) = match applicable(services, &id) {
        Ok(found) => found,
        Err(refusal) => return refusal.page(shell),
    };
    saved::sweep(services, state.unix_seconds());
    let locale = user.locale();
    let rows = runs(
        &services.store(),
        user.username(),
        |record| matches!(record.origin(), Origin::Preset { id: known, name: _ } if *known == id),
    );
    let mut args = FluentArgs::new();
    args.set("name", name);
    errors::render(&Landing {
        title: tr(locale, keys::WEB_PRESETS_APPLY_TITLE, Some(&args)),
        intro: tr(locale, keys::WEB_PRESETS_APPLY_INTRO, None),
        start: format!("/ui/presets/{id}/apply"),
        start_label: tr(locale, keys::WEB_PRESETS_APPLY_START, None),
        table: runs_view(&rows, locale),
        shell,
    })
}

/// `POST /ui/copy`: starts a copy at its source step.
///
/// # Errors
///
/// Answers 503 without the fleet and the audited 403 without `Migrate`.
// NOT cancel-safe: see `start`.
pub(super) async fn copy_start(
    State(state): State<WebState>,
    Extension(runs): Extension<Arc<Wizards<Record>>>,
    user: CurrentUser,
) -> Result<Response, Answer> {
    let services = Services::of(&state, &user).map_err(Refusal::status)?;
    if !user.role().grants(Permission::Migrate) {
        Audit::new("web.preset_run_start", String::new())
            .with_params(json!({ "kind": "copy" }))
            .append(&state, &user, "forbidden")
            .await;
        return Err(errors::response(Kind::Forbidden, fragment_shell(user.locale())).into());
    }
    saved::sweep(services, state.unix_seconds());
    start(&state, (services, &runs), Origin::Copy, None).await
}

/// `POST /ui/presets/{id}/apply`: starts applying the preset at its target step.
///
/// # Errors
///
/// Answers 503 without the fleet, 404 for a preset the user does not see and the audited
/// 403 without `Migrate` on its source router.
// NOT cancel-safe: see `start`.
pub(super) async fn preset_start(
    State(state): State<WebState>,
    Path(id): Path<String>,
    Extension(runs): Extension<Arc<Wizards<Record>>>,
    user: CurrentUser,
) -> Result<Response, Answer> {
    let services = Services::of(&state, &user).map_err(Refusal::status)?;
    let (name, source) = match applicable(services, &id) {
        Ok(found) => found,
        Err(Refusal::Forbidden) => {
            Audit::new("web.preset_run_start", id)
                .with_params(json!({ "kind": "preset" }))
                .append(&state, &user, "forbidden")
                .await;
            return Err(errors::response(Kind::Forbidden, fragment_shell(user.locale())).into());
        }
        Err(refusal) => return Err(refusal.status().into()),
    };
    let origin = Origin::Preset { id, name };
    start(&state, (services, &runs), origin, source).await
}

/// Creates a run of `origin` from `source_router` for the user of `services` and opens it.
///
/// # Errors
///
/// Answers 500 when the random generator or the state directory fails.
// NOT cancel-safe: an abandoned append may still be written.
async fn start(
    state: &WebState,
    (services, runs): (Services<'_>, &Wizards<Record>),
    origin: Origin,
    source_router: Option<String>,
) -> Result<Response, Answer> {
    let user = services.user();
    let locale = user.locale();
    let now = state.unix_seconds();
    let kind = match origin {
        Origin::Preset { id: _, name: _ } => "preset",
        Origin::Copy => "copy",
    };
    let params = json!({ "kind": kind, "reason": "limit" });
    if let Some(refused) =
        retention::refusal::<Record>(services, now, ("web.preset_run_start", params)).await
    {
        return Err(refused);
    }
    let id = fresh_id(now).ok_or_else(|| {
        Answer::from(errors::internal(
            "the random generator failed",
            fragment_shell(locale),
        ))
    })?;

    let record = Record::new((id, user.username().to_owned()), now, origin, source_router);
    if let Err(error) = services.store().save(&record) {
        return Err(errors::internal(&error, fragment_shell(locale)).into());
    }
    drop(runs.session(record.id()));
    let audit = record.source_router().map_or_else(
        || Audit::new("web.preset_run_start", record.id().to_owned()),
        |router| Audit::on_router("web.preset_run_start", router, record.id().to_owned()),
    );
    audit
        .with_params(json!({ "kind": kind }))
        .append(state, user, "started")
        .await;
    Ok(screen::moved(&record))
}

/// The name and source router of preset `id` when the user sees it (404 otherwise) and
/// may migrate with its source (403 otherwise).
///
/// # Errors
///
/// Returns the refusal.
fn applicable(services: Services<'_>, id: &str) -> Result<(String, Option<String>), Refusal> {
    let user = services.user();
    if !user.role().grants(Permission::Migrate) {
        return Err(Refusal::Forbidden);
    }
    let presets = saved::store(services.fleet())
        .list(user.role())
        .map_err(|error| Refusal::Failed(Box::new(error)))?;
    let preset = presets
        .into_iter()
        .find(|preset| preset.id == id)
        .ok_or(Refusal::Missing)?;
    let source = preset.source.router_id.clone();
    if source
        .as_deref()
        .is_some_and(|router| !services.may_migrate(router))
    {
        return Err(Refusal::Forbidden);
    }
    Ok((preset.name, source))
}

/// The runs of `owner` that `keep` keeps, newest first.
fn runs<F>(store: &Store, owner: &str, keep: F) -> Vec<Record>
where
    F: Fn(&Record) -> bool,
{
    let mut records = store.list::<Record>(owner).unwrap_or_else(|error| {
        tracing::warn!(%error, "preset runs could not be listed");
        Vec::new()
    });
    records.retain(|record| keep(record));
    records
}

/// The table of the runs `records` in `locale`.
fn runs_view(records: &[Record], locale: Locale) -> TableView {
    let columns = [
        keys::WEB_PRESETS_RUNS_STARTED,
        keys::WEB_PRESETS_RUNS_SETTINGS,
        keys::MIGRATE_TARGET,
        keys::WEB_PRESETS_RUNS_STEP,
    ];
    let rows = records.iter().map(|record| row(record, locale)).collect();
    runs_table((&columns, keys::WEB_PRESETS_RUNS_EMPTY), rows, locale)
}

/// The list row of `record`: started, settings, target and step.
fn row(record: &Record, locale: Locale) -> Vec<Cell> {
    let href = screen::href::<Record>(record.id());
    vec![
        started(href, Timestamp::at(record.created_at(), locale), locale),
        Cell::text(summary::settings_text(record, locale)),
        Cell::code(record.target().unwrap_or_default().to_owned()),
        Cell::text(format!(
            "{}. {}",
            record.step().number(),
            tr(locale, record.step().label(), None)
        )),
    ]
}
