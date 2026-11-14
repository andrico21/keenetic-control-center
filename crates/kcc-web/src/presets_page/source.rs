//! Step 1 of a copy: the source router and the settings groups.
//!
//! kcc reads the router's saved configuration once, keeps only the chosen groups'
//! settings and seals them in the run's directory as its transient preset.

use alloc::sync::Arc;

use askama::Template;
use axum::{
    Extension, Form,
    extract::{Path, State},
    response::Response,
};
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
};
use kcc_migrate::presets::{
    groups::SettingsGroupEngine,
    model::{CaptureRequest, Preset, PresetSource, PresetSourceKind},
};
use kcc_rci::ConfigKind;
use secrecy::{ExposeSecret as _, SecretString};
use serde_json::json;

use super::{
    access::Visit,
    capture::facts,
    lines::group_words,
    saved, screen,
    steps::{Origin, Step},
};
use crate::{
    WebState,
    authz::CurrentUser,
    errors,
    migrate_wizard::{access::Services, analysis::parse_source, kinds::Source, service::Wizards},
    page::{Localize as _, Shell},
    page_kit::{
        audit::Record as Audit,
        context::{Refusal, fragment_shell},
        respond::{self, Answer},
    },
};

/// The step's panel.
#[derive(Template)]
#[template(path = "partials/presets_source.html")]
pub(super) struct Panel {
    /// Locale carrier.
    shell: Shell,
    /// Run id.
    id: String,
    /// Routers the user may copy from, and whether each is chosen.
    routers: Vec<(String, bool)>,
    /// Every group: id, name, description, whether chosen.
    groups: Vec<(String, String, String, bool)>,
    /// The router select's error.
    router_error: String,
    /// The groups' error.
    groups_error: String,
}

localized!(Panel);

impl Panel {
    /// The panel of run `id` with `router` and `groups` chosen.
    // cancel-safe: reads only.
    pub(super) async fn new(
        services: Services<'_>,
        id: &str,
        (router, groups): (Option<&str>, &[String]),
    ) -> Self {
        let locale = services.user().locale();
        let routers = match services.fleet().visible(services.user().role()).await {
            Ok(entries) => entries
                .into_iter()
                .map(|entry| entry.profile.id)
                .filter(|known| services.may_migrate(known))
                .map(|known| {
                    let chosen = router == Some(known.as_str());
                    (known, chosen)
                })
                .collect(),
            Err(error) => {
                tracing::warn!(%error, "copy source: routers could not be listed");
                Vec::new()
            }
        };
        let all = SettingsGroupEngine::embedded()
            .and_then(SettingsGroupEngine::groups)
            .unwrap_or_default();
        Self {
            shell: fragment_shell(locale),
            id: id.to_owned(),
            routers,
            groups: all
                .iter()
                .filter_map(|group| {
                    let (title, text) = group_words(&group.id)?;
                    Some((
                        group.id.clone(),
                        tr(locale, title, None),
                        tr(locale, text, None),
                        groups.contains(&group.id),
                    ))
                })
                .collect(),
            router_error: String::new(),
            groups_error: String::new(),
        }
    }
}

/// `POST /ui/presets/runs/{run}/source`: reads the router, keeps the chosen groups'
/// settings sealed and moves on to the target.
///
/// # Errors
///
/// Answers the refusal of the run, and the panel with its errors (422): a router the
/// user may not migrate with is refused before any request to it.
// NOT cancel-safe: an abandoned append may still be written.
pub(super) async fn submit(
    State(state): State<WebState>,
    Path(id): Path<String>,
    Extension(runs): Extension<Arc<Wizards>>,
    user: CurrentUser,
    Form(form): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let services = Services::of(&state, &user).map_err(Refusal::status)?;
    let mut visit = Visit::open(services, &runs, &id)
        .await
        .map_err(Refusal::status)?;
    if visit.record().step() != Step::Source || *visit.record().origin() != Origin::Copy {
        return Ok(screen::moved(visit.record()));
    }
    let locale = user.locale();
    let router = form
        .iter()
        .rev()
        .find(|(name, _)| name == "router")
        .map_or_else(String::new, |(_, value)| value.trim().to_owned());
    let groups = form
        .iter()
        .filter(|(name, _)| name == "group")
        .map(|(_, value)| value.clone())
        .filter(|group| group_words(group).is_some())
        .collect::<Vec<_>>();
    let chosen = (Some(router.as_str()), groups.as_slice());
    if !services.permits(&router).await {
        Audit::new("web.preset_copy_source", id.clone())
            .append(&state, &user, "forbidden")
            .await;
        let refusal = (true, keys::WEB_MIGRATE_SOURCE_ERROR_ROUTER);
        return Err(refused(services, &id, chosen, refusal).await);
    }
    if groups.is_empty() {
        let refusal = (false, keys::WEB_PRESETS_ERROR_GROUPS);
        return Err(refused(services, &id, chosen, refusal).await);
    }
    let preset = match copied(services, (&id, &router), &groups, state.unix_seconds()).await {
        Ok(found) => found,
        Err(refusal) => return Err(refused(services, &id, chosen, refusal).await),
    };
    if let Err(error) = saved::seal(services, &id, &preset) {
        return Err(errors::internal(&error, fragment_shell(locale)).into());
    }
    visit.session().forget();
    visit.record_mut().choose_source(router.clone());
    if let Err(error) = visit.save() {
        return Err(errors::internal(&error, fragment_shell(locale)).into());
    }
    Audit::on_router("web.preset_copy_source", &router, id)
        .with_params(json!({ "groups": preset.groups, "settings": preset.lines.len() }))
        .append(&state, &user, "read")
        .await;
    Ok(screen::moved(visit.record()))
}

/// The transient preset of run `id` copying `groups` from `router`, read at `now`.
///
/// # Errors
///
/// Returns whether the problem is the router's (else the groups') and its message.
// cancel-safe: reads only.
async fn copied(
    services: Services<'_>,
    (id, router): (&str, &str),
    groups: &[String],
    now: u64,
) -> Result<Preset, (bool, MessageKey)> {
    let unread = (true, keys::WEB_MIGRATE_SOURCE_ERROR_READ);
    let client = services
        .fleet()
        .registry()
        .client(router)
        .await
        .map_err(|_error| unread)?;
    let bytes = client
        .download_config(ConfigKind::Startup)
        .await
        .map_err(|error| {
            tracing::warn!(%error, router, "copy source: saved configuration not read");
            unread
        })?;
    let text = String::from_utf8(bytes.expose_secret().to_vec())
        .map(SecretString::from)
        .map_err(|_error| (true, keys::WEB_MIGRATE_SOURCE_ERROR_PARSE))?;
    let config =
        parse_source(&text).map_err(|_problem| (true, keys::WEB_MIGRATE_SOURCE_ERROR_PARSE))?;
    let source = Source::Router {
        router: router.to_owned(),
    };
    let (model, firmware) = facts(services, &source, &text)
        .await
        .ok_or((true, keys::WEB_PRESETS_FIRMWARE_MISSING))?;
    let chosen = groups.iter().map(String::as_str).collect::<Vec<_>>();
    let selection = SettingsGroupEngine::embedded()
        .and_then(|engine| engine.select(&config.ast, &chosen))
        .map_err(|_error| (false, keys::WEB_PRESETS_ERROR_GROUPS))?;
    if selection.lines.is_empty() {
        return Err((false, keys::WEB_PRESETS_ERROR_GROUPS));
    }
    let facts = PresetSource::new(
        PresetSourceKind::Router,
        Some(router.to_owned()),
        model,
        firmware,
        now,
    );
    let request = CaptureRequest::new(
        id.to_owned(),
        router.to_owned(),
        String::new(),
        groups.to_vec(),
        facts,
        services.user().username().to_owned(),
    );
    Ok(Preset::captured(request, selection))
}

/// The panel of run `id` as `chosen`, with the message of `refusal` beside the router
/// select (when its flag is set) or the groups, as 422.
// cancel-safe: reads only.
async fn refused(
    services: Services<'_>,
    id: &str,
    chosen: (Option<&str>, &[String]),
    (on_router, key): (bool, MessageKey),
) -> Answer {
    let mut panel = Panel::new(services, id, chosen).await;
    let message = tr(services.user().locale(), key, None);
    if on_router {
        panel.router_error = message;
    } else {
        panel.groups_error = message;
    }
    respond::unprocessable(&panel).into()
}
