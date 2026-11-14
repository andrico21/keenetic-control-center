//! Step 1: where the configuration comes from: a router of the fleet (its startup
//! configuration, read once), an uploaded startup-config file, or a stored backup.
//!
//! The text must parse as a router configuration (its checksum too); it is sealed beside
//! the record, which only names where it came from. The form is `multipart/form-data`
//! because of the file; the route's body limit is 1 MiB, and a larger upload is answered
//! with the localized size error beside the file input.
//!
//! A new preset (`/ui/presets/new`) asks for its source with the same panel, posted to
//! its own route.

use alloc::sync::Arc;

use askama::Template;
use axum::{
    Extension,
    extract::{Multipart, Path, State, multipart::MultipartRejection},
    response::Response,
};
use fluent_bundle::FluentArgs;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};
use serde_json::json;

use super::{
    access::{Services, Visit},
    kinds::{Mode, Source, Step},
    screen,
    service::Wizards,
    source_read,
};
use crate::{
    WebState,
    admin_shared::Timestamp,
    authz::CurrentUser,
    errors,
    page::{Localize as _, Shell},
    page_kit::{
        audit::Record as Audit,
        context::{Refusal, fragment_shell},
        respond::{self, Answer},
    },
};

/// The step's panel.
#[derive(Template)]
#[template(path = "partials/migrate_source.html")]
pub(crate) struct Panel {
    /// Locale carrier.
    shell: Shell,
    /// Where the form posts.
    action: String,
    /// The panel's title and the sentence under it.
    words: (MessageKey, MessageKey),
    /// The chosen kind: `router`, `file` or `backup`.
    kind: &'static str,
    /// Routers the user may migrate from.
    routers: Vec<Choice>,
    /// Their stored backups, per router.
    groups: Vec<Group>,
    /// Field errors.
    errors: Errors,
}

localized!(Panel);

/// One option of a select.
struct Choice {
    /// The value sent.
    value: String,
    /// The text shown.
    label: String,
    /// Whether it is selected.
    selected: bool,
}

/// The backups of one router.
struct Group {
    /// Router profile id.
    router: String,
    /// Its backups, newest first.
    backups: Vec<Choice>,
}

/// The form's field errors; empty when none.
#[derive(Default)]
struct Errors {
    /// The kind choice.
    kind: String,
    /// The router select.
    router: String,
    /// The file input.
    file: String,
    /// The backup select.
    backup: String,
}

/// Which field a refusal belongs to.
#[derive(Clone, Copy)]
pub(crate) enum Field {
    /// The kind choice.
    Kind,
    /// The router select.
    Router,
    /// The file input.
    File,
    /// The backup select.
    Backup,
}

impl Panel {
    /// The panel of migration `id`, with `source` chosen.
    // cancel-safe: reads only.
    pub(super) async fn new(services: Services<'_>, id: &str, source: Option<&Source>) -> Self {
        Self::posting(services, format!("/ui/migrate/{id}/source"), source).await
    }

    /// The panel posting to `action` with the `(title, text)` words of a new preset.
    // cancel-safe: reads only.
    pub(crate) async fn for_preset(
        services: Services<'_>,
        action: String,
        words: (MessageKey, MessageKey),
    ) -> Self {
        let mut panel = Self::posting(services, action, None).await;
        panel.words = words;
        panel
    }

    /// The panel posting to `action`, with `source` chosen.
    // cancel-safe: reads only.
    async fn posting(services: Services<'_>, action: String, source: Option<&Source>) -> Self {
        let locale = services.user().locale();
        let chosen = |value: &str| match source {
            Some(Source::Router { router }) => router == value,
            Some(Source::Backup { router, name }) => format!("{router}/{name}") == value,
            Some(Source::File { name: _ }) | None => false,
        };
        let routers = match services.fleet().visible(services.user().role()).await {
            Ok(entries) => entries
                .into_iter()
                .map(|entry| entry.profile.id)
                .filter(|router| services.may_migrate(router))
                .collect::<Vec<_>>(),
            Err(error) => {
                tracing::warn!(%error, "migration source: routers could not be listed");
                Vec::new()
            }
        };
        let groups = routers
            .iter()
            .filter_map(|router| {
                let backups = services.fleet().workflow().backups().list(router).ok()?;
                (!backups.is_empty()).then(|| Group {
                    router: router.clone(),
                    backups: backups
                        .into_iter()
                        .map(|backup| {
                            let value = format!("{router}/{}", backup.name);
                            let mut args = FluentArgs::new();
                            args.set(
                                "value",
                                Timestamp::at(backup.created_at)
                                    .map_or_else(String::new, |time| time.text().to_owned()),
                            );
                            args.set("name", backup.reason);
                            Choice {
                                selected: chosen(&value),
                                label: tr(
                                    locale,
                                    keys::WEB_MIGRATE_SOURCE_BACKUP_OPTION,
                                    Some(&args),
                                ),
                                value,
                            }
                        })
                        .collect(),
                })
            })
            .collect();
        Self {
            shell: fragment_shell(locale),
            action,
            words: (
                keys::WEB_MIGRATE_SOURCE_TITLE,
                keys::WEB_MIGRATE_SOURCE_TEXT,
            ),
            kind: match source {
                Some(Source::File { name: _ }) => "file",
                Some(Source::Backup { router: _, name: _ }) => "backup",
                Some(Source::Router { router: _ }) | None => "router",
            },
            routers: routers
                .into_iter()
                .map(|router| Choice {
                    selected: chosen(&router),
                    label: router.clone(),
                    value: router,
                })
                .collect(),
            groups,
            errors: Errors::default(),
        }
    }

    /// The panel with `message` beside `field`, the kind `kind` chosen.
    pub(crate) fn refusing(mut self, kind: &'static str, field: Field, message: String) -> Self {
        self.kind = kind;
        let slot = match field {
            Field::Kind => &mut self.errors.kind,
            Field::Router => &mut self.errors.router,
            Field::File => &mut self.errors.file,
            Field::Backup => &mut self.errors.backup,
        };
        *slot = message;
        self
    }
}

/// `POST /ui/migrate/{id}/source`: reads and checks the chosen source, seals it and moves
/// on to the target.
///
/// # Errors
///
/// Answers the refusal of the migration, and the panel with its field error (422).
pub(super) async fn submit(
    State(state): State<WebState>,
    Path(id): Path<String>,
    Extension(wizards): Extension<Arc<Wizards>>,
    user: CurrentUser,
    multipart: Result<Multipart, MultipartRejection>,
) -> Result<Response, Answer> {
    let services = Services::of(&state, &user).map_err(Refusal::status)?;
    let mut visit = Visit::open(services, &wizards, &id)
        .await
        .map_err(Refusal::status)?;
    let session = visit.session();
    if visit.record().step() != Step::Source || visit.record().mode() == Mode::Restore {
        return Ok(screen::moved(visit.record()));
    }
    let locale = user.locale();
    let panel = Panel::new(services, &id, None).await;
    let submitted = match multipart {
        Ok(fields) => source_read::read(fields).await,
        Err(_rejection) => Err(keys::WEB_MIGRATE_SOURCE_ERROR_FILE),
    };
    let form = match submitted {
        Ok(found) => found,
        Err(message) => {
            return Err(refuse(panel, "file", Field::File, message, locale));
        }
    };
    let (kind, chosen) = source_read::choose(services, form).await;
    let (source, text) = match chosen {
        Ok(found) => found.into_parts(),
        Err((field, message)) => return Err(refuse(panel, kind, field, message, locale)),
    };
    if let Err(error) = visit.seal_source(&text) {
        return Err(errors::internal(&error, fragment_shell(locale)).into());
    }
    let router = source.router().map(str::to_owned);
    visit.record_mut().choose_source(source);
    session.forget();
    if let Err(error) = visit.save() {
        return Err(errors::internal(&error, fragment_shell(locale)).into());
    }
    let audit = match router {
        Some(found) => Audit::on_router("web.migrate_source", &found, id),
        None => Audit::new("web.migrate_source", id),
    };
    audit
        .with_params(json!({ "kind": kind }))
        .append(&state, &user, "chosen")
        .await;
    Ok(screen::moved(visit.record()))
}

/// The panel refusing the submit with `message` beside `field`, as 422.
pub(crate) fn refuse(
    panel: Panel,
    kind: &'static str,
    field: Field,
    message: MessageKey,
    locale: Locale,
) -> Answer {
    let refused = panel.refusing(kind, field, tr(locale, message, None));
    respond::unprocessable(&refused).into()
}
