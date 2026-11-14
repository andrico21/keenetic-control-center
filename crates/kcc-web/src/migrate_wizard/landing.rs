//! The migrations page at `/ui/migrate`.
//!
//! It holds Start migration, the user's own migrations, and the restore offer the
//! configuration page links to: `/ui/migrate?mode=restore&router=<id>&backup=<name>` (a
//! stable route: the offer is checked here and again when it is started). The same
//! offer answers `?source=backup&router=<id>&backup=<name>[&target=<id>]` when the
//! target is the backup's own router.

use alloc::sync::Arc;

use askama::Template;
use axum::{
    Extension, Form,
    extract::{Query, State},
    http::HeaderMap,
    response::Response,
};
use fluent_bundle::FluentArgs;
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use secrecy::SecretString;
use serde::Deserialize;
use serde_json::json;

use super::{kinds::Mode, record::Record, summary::source_text};
use crate::{
    WebState,
    admin_shared::Timestamp,
    authz::{CurrentSession, CurrentUser},
    errors,
    nav::Section,
    page::{Localize as _, Shell},
    page_kit::{
        audit::Record as Audit,
        context::{Caller, Refusal, fragment_shell},
        outcome::{Failure, Outcome},
        respond::Answer,
    },
    table::{cells::Cell, view::TableView},
    wizard::{
        analysis::parse_source,
        flow::{Flow as _, Stage as _},
        ids::fresh_id,
        runs, screen,
        service::Wizards,
        services::Services,
        store::Sealed,
    },
};

/// The query of the restore offer.
#[derive(Debug, Default, Deserialize)]
pub(super) struct Offer {
    /// `restore` asks for the offer.
    mode: Option<String>,
    /// `backup` asks for it too, when `target` is absent or the backup's router.
    source: Option<String>,
    /// The router the backup belongs to.
    router: Option<String>,
    /// The backup's file name.
    backup: Option<String>,
    /// The router restored onto.
    target: Option<String>,
}

impl Offer {
    /// Whether the query asks for a restore offer.
    fn asked(&self) -> bool {
        self.mode.as_deref() == Some("restore")
            || (self.source.as_deref() == Some("backup")
                && self
                    .target
                    .as_ref()
                    .is_none_or(|target| Some(target) == self.router.as_ref()))
    }
}

/// The migrations page.
#[derive(Template)]
#[template(path = "pages/migrate_landing.html")]
struct Landing {
    /// Page shell.
    shell: Shell,
    /// The restore offer, when the query asked for one that can be started.
    restore: Option<Restore>,
    /// Whether the query asked for a restore that cannot be offered.
    restore_refused: bool,
    /// The user's migrations, newest first.
    table: TableView,
}

localized!(Landing);

/// An offered restore.
struct Restore {
    /// The router.
    router: String,
    /// The backup's file name.
    backup: String,
    /// The sentence describing it.
    text: String,
}

/// `GET /ui/migrate`: the page.
pub(super) async fn page(
    State(state): State<WebState>,
    Query(offer): Query<Offer>,
    headers: HeaderMap,
    current: CurrentSession,
    user: CurrentUser,
) -> Response {
    let shell = Caller::new(&headers, &current, &user)
        .shell(&state, Section::Migration, None)
        .await;
    let services = match Services::of(&state, &user) {
        Ok(found) => found,
        Err(refusal) => return refusal.page(shell),
    };
    let locale = user.locale();
    let asked = offer.asked();
    let restore = if asked {
        offered(services, offer.router.as_deref(), offer.backup.as_deref())
            .await
            .map(|(router, backup, _text)| {
                let mut args = FluentArgs::new();
                args.set("router", router.clone());
                args.set("name", backup.clone());
                Restore {
                    text: tr(locale, keys::WEB_MIGRATE_RESTORE_OFFER, Some(&args)),
                    router,
                    backup,
                }
            })
    } else {
        None
    };
    let rows = match services.store().list(user.username()) {
        Ok(records) => records.iter().map(|record| row(record, locale)).collect(),
        Err(error) => return Refusal::Failed(Box::new(error)).page(shell),
    };
    let columns = [
        keys::WEB_MIGRATE_LIST_STARTED,
        keys::WEB_MIGRATE_LIST_KIND,
        keys::WEB_MIGRATE_SUMMARY_SOURCE,
        keys::MIGRATE_TARGET,
        keys::WEB_MIGRATE_LIST_STEP,
    ];
    let empty = keys::WEB_MIGRATE_LIST_EMPTY;
    errors::render(&Landing {
        restore_refused: asked && restore.is_none(),
        restore,
        table: runs::runs_table((&columns, empty), rows, locale),
        shell,
    })
}

/// The form starting a migration or the offered restore.
#[derive(Debug, Deserialize)]
pub(super) struct Start {
    /// `migrate` or `restore`.
    mode: String,
    /// The restore's router.
    #[serde(default)]
    router: Option<String>,
    /// The restore's backup.
    #[serde(default)]
    backup: Option<String>,
}

/// `POST /ui/migrate`: creates the migration and opens its first step.
///
/// # Errors
///
/// Answers 503 without the fleet, and the refusal of a restore that cannot be started.
pub(super) async fn start(
    State(state): State<WebState>,
    Extension(wizards): Extension<Arc<Wizards<Record>>>,
    user: CurrentUser,
    Form(start): Form<Start>,
) -> Result<Response, Answer> {
    let services = Services::of(&state, &user).map_err(Refusal::status)?;
    let locale = user.locale();
    let id = fresh_id(state.unix_seconds()).ok_or_else(|| {
        Answer::from(errors::internal(
            "the random generator failed",
            fragment_shell(locale),
        ))
    })?;
    let owner = user.username().to_owned();
    let now = state.unix_seconds();
    let (record, sealed) = match start.mode.as_str() {
        "restore" => {
            let Some((router, backup, text)) =
                offered(services, start.router.as_deref(), start.backup.as_deref()).await
            else {
                Audit::new("web.migrate_start", id)
                    .with_params(json!({ "mode": "restore" }))
                    .append(&state, &user, "refused")
                    .await;
                let failure = Failure::new(
                    tr(locale, keys::WEB_MIGRATE_RESTORE_INVALID, None),
                    "refused",
                );
                return Err(Outcome::failed(failure).render(locale).into());
            };
            (
                Record::restore(id, owner, now, (router, backup)),
                Some(text),
            )
        }
        _ => (Record::new(id, owner, now), None),
    };
    let store = services.store();
    let saved = store.save(&record).and_then(|()| {
        sealed.as_ref().map_or(Ok(()), |text| {
            store.seal(services.key(), record.id(), Sealed::Source, text)
        })
    });
    if let Err(error) = saved {
        return Err(errors::internal(&error, fragment_shell(locale)).into());
    }
    drop(wizards.session(record.id()));
    let audit = record
        .source()
        .and_then(|source| source.router())
        .map_or_else(
            || Audit::new("web.migrate_start", record.id().to_owned()),
            |router| Audit::on_router("web.migrate_start", router, record.id().to_owned()),
        );
    let mode = match record.mode() {
        Mode::Migrate => "migrate",
        Mode::Restore => "restore",
    };
    audit
        .with_params(json!({ "mode": mode }))
        .append(&state, &user, "started")
        .await;
    Ok(screen::moved(&record))
}

/// The backup `backup` of `router` with its text, when the user may restore it: the
/// role may migrate the router, sees it, and the backup parses as a configuration.
// cancel-safe: reads only.
async fn offered(
    services: Services<'_>,
    asked_router: Option<&str>,
    asked_backup: Option<&str>,
) -> Option<(String, String, SecretString)> {
    let (router, backup) = (asked_router?, asked_backup?);
    if !services.permits(router).await {
        return None;
    }
    let text = services
        .fleet()
        .workflow()
        .backups()
        .get(router, backup)
        .ok()?;
    parse_source(&text).ok().map(drop)?;
    Some((router.to_owned(), backup.to_owned(), text))
}

/// The list row of `record`: started, kind, source, target and step.
fn row(record: &Record, locale: Locale) -> Vec<Cell> {
    let kind = match record.mode() {
        Mode::Migrate => keys::WEB_MIGRATE_KIND_MIGRATION,
        Mode::Restore => keys::WEB_MIGRATE_KIND_RESTORE,
    };
    let href = screen::href::<Record>(record.id());
    vec![
        runs::started(href, Timestamp::at(record.created_at()), locale),
        Cell::word(locale, kind),
        Cell::text(
            record
                .source()
                .map_or_else(String::new, |source| source_text(source, locale)),
        ),
        Cell::code(record.target().unwrap_or_default().to_owned()),
        Cell::text(format!(
            "{}. {}",
            record.step().number(),
            tr(locale, record.step().label(), None)
        )),
    ]
}
