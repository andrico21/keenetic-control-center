//! A new preset's source at `/ui/presets/new`.
//!
//! A router of the fleet (its saved configuration), a stored backup or an uploaded
//! startup-config file, read with the migration wizard's first step and kept as a draft
//! in memory.

use alloc::sync::Arc;

use askama::Template;
use axum::{
    Extension,
    extract::{Multipart, State, multipart::MultipartRejection},
    http::HeaderMap,
    response::Response,
};
use kcc_app::permissions::Permission;
use kcc_i18n::{bundle::MessageKey, keys};
use kcc_migrate::source::SourceConfig;
use secrecy::{ExposeSecret as _, SecretString};
use serde_json::json;

use super::drafts::{Draft, Drafts};
use crate::{
    WebState,
    authz::{CurrentSession, CurrentUser},
    errors::{self, Kind},
    migrate_wizard::{
        kinds::Source,
        source::{self, Field, Panel},
        source_read,
    },
    nav::Section,
    page::{Localize as _, Shell},
    page_kit::{
        audit::Record as Audit,
        context::{Caller, Refusal, fragment_shell},
        respond::{self, Answer},
    },
    wizard::{ids::fresh_id, services::Services},
};

/// Where the source form posts.
const ACTION: &str = "/ui/presets/new";

/// The source panel's words.
const WORDS: (MessageKey, MessageKey) = (
    keys::WEB_MIGRATE_SOURCE_TITLE,
    keys::WEB_PRESETS_NEW_SOURCE_TEXT,
);

/// The new preset page around the source panel.
#[derive(Template)]
#[template(path = "pages/presets_new.html")]
struct Capture {
    /// Page shell.
    shell: Shell,
    /// The rendered source panel.
    panel: String,
}

localized!(Capture);

/// `GET /ui/presets/new`: the source form.
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
    if !user.role().grants(Permission::Migrate) {
        return errors::response(Kind::Forbidden, shell);
    }
    let panel = Panel::for_preset(services, ACTION.to_owned(), WORDS).await;
    match panel.render() {
        Ok(html) => errors::render(&Capture { shell, panel: html }),
        Err(error) => errors::internal(&error, shell),
    }
}

/// `POST /ui/presets/new`: reads and checks the chosen source and opens its groups.
///
/// # Errors
///
/// Answers 503 without the fleet, the audited 403 without `Migrate`, and the panel with
/// its field error (422).
// NOT cancel-safe: the draft is kept before the audit append.
pub(super) async fn read(
    State(state): State<WebState>,
    Extension(drafts): Extension<Arc<Drafts>>,
    user: CurrentUser,
    multipart: Result<Multipart, MultipartRejection>,
) -> Result<Response, Answer> {
    let services = Services::of(&state, &user).map_err(Refusal::status)?;
    let locale = user.locale();
    if !user.role().grants(Permission::Migrate) {
        Audit::new("web.preset_source", String::new())
            .append(&state, &user, "forbidden")
            .await;
        return Err(errors::response(Kind::Forbidden, fragment_shell(locale)).into());
    }
    let panel = Panel::for_preset(services, ACTION.to_owned(), WORDS).await;
    let submitted = match multipart {
        Ok(fields) => source_read::read(fields).await,
        Err(_rejection) => Err(keys::WEB_MIGRATE_SOURCE_ERROR_FILE),
    };
    let form = match submitted {
        Ok(found) => found,
        Err(message) => return Err(source::refuse(panel, "file", Field::File, message, locale)),
    };
    let (kind, chosen) = source_read::choose(services, form).await;
    let (found, text) = match chosen {
        Ok(read) => read.into_parts(),
        Err((field, message)) => return Err(source::refuse(panel, kind, field, message, locale)),
    };
    let Some(facts) = facts(services, &found, &text).await else {
        let field = match found {
            Source::File { name: _ } => Field::File,
            Source::Router { router: _ } | Source::Backup { router: _, name: _ } => Field::Kind,
        };
        let message = keys::WEB_PRESETS_FIRMWARE_MISSING;
        return Err(source::refuse(panel, kind, field, message, locale));
    };
    let now = state.unix_seconds();
    let id = fresh_id(now).ok_or_else(|| {
        Answer::from(errors::internal(
            "the random generator failed",
            fragment_shell(locale),
        ))
    })?;
    let audit = found.router().map_or_else(
        || Audit::new("web.preset_source", id.clone()),
        |router| Audit::on_router("web.preset_source", router, id.clone()),
    );
    let owner = (user.username().to_owned(), now);
    drafts.keep(id.clone(), Draft::new(owner, found, facts, text), now);
    audit
        .with_params(json!({ "kind": kind }))
        .append(&state, &user, "read")
        .await;
    Ok(respond::open(&format!("/ui/presets/new/{id}")))
}

/// The model and firmware version a preset of `source`, whose text is `text`, records:
/// a router's own report, else the configuration's header; `None` without a firmware
/// version.
// cancel-safe: reads only.
pub(super) async fn facts(
    services: Services<'_>,
    source: &Source,
    text: &SecretString,
) -> Option<(String, String)> {
    let config = SourceConfig::from_bytes(text.expose_secret().as_bytes()).ok()?;
    let reported = match source {
        Source::Router { router } => match services.fleet().registry().client(router).await {
            Ok(client) => client
                .detect()
                .await
                .map_err(|error| tracing::warn!(%error, router, "preset source not detected"))
                .ok(),
            Err(error) => {
                tracing::warn!(%error, router, "preset source: no router client");
                None
            }
        },
        Source::File { name: _ } | Source::Backup { router: _, name: _ } => None,
    };
    let model = reported
        .as_ref()
        .and_then(|info| {
            info.version
                .model
                .clone()
                .or_else(|| info.hw_id().map(str::to_owned))
        })
        .or_else(|| config.header.model.clone())
        .unwrap_or_default();
    let firmware = reported
        .and_then(|info| info.firmware)
        .or(config.firmware)?;
    Some((model, firmware.to_string()))
}
