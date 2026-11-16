//! Reveal: the separate, audited action showing secret values in plaintext.
//!
//! It needs `RevealSecrets`. A preset's (`POST /ui/presets/{id}/reveal`) shows its
//! settings that carry one; a run's (`POST /ui/presets/runs/{run}/reveal`) the previewed
//! commands that carry one. Every other page shows them redacted; the audit log records
//! the action and how many lines it showed, never a value.

use alloc::sync::Arc;

use askama::Template;
use axum::{
    Extension,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse as _, Response},
};
use fluent_bundle::FluentArgs;
use kcc_app::permissions::Permission;
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_migrate::planner::PlannedLine;
use secrecy::{ExposeSecret, SecretString};
use serde_json::json;

use super::{
    access::Visit, lines::secret, list::may_change, plan::Basis, record::Record, saved,
    summary::settings_text,
};
use crate::{
    WebState,
    authz::CurrentUser,
    errors::{self, Kind},
    page::{Localize as _, Shell},
    page_kit::{
        audit::Record as Audit,
        context::{Refusal, fragment_shell},
        gate::allowed,
        respond::Answer,
    },
    wizard::{flow::Flow as _, service::Wizards, services::Services},
};

/// The dialog of one Reveal: the lines carrying a secret, in plaintext.
#[derive(Template)]
#[template(path = "partials/presets_reveal.html")]
struct Revealed {
    /// Locale carrier.
    shell: Shell,
    /// "Secret values of <name>".
    title: String,
    /// The lines; only this dialog's markup reads them.
    lines: Vec<SecretString>,
}

localized!(Revealed);

impl Revealed {
    /// The dialog titled after `name`, showing `lines`.
    fn new(locale: Locale, name: String, lines: Vec<SecretString>) -> Self {
        let mut args = FluentArgs::new();
        args.set("name", name);
        Self {
            shell: fragment_shell(locale),
            title: tr(locale, keys::WEB_PRESETS_REVEAL_TITLE, Some(&args)),
            lines,
        }
    }

    /// The lines, for the dialog's list.
    fn shown(&self) -> Vec<&str> {
        self.lines.iter().map(ExposeSecret::expose_secret).collect()
    }
}

/// `POST /ui/presets/{id}/reveal`: the preset's settings carrying a secret value.
///
/// # Errors
///
/// Answers 404 for a preset the user does not see and the audited 403 without
/// `RevealSecrets` and `Migrate` on its source router.
// NOT cancel-safe: an abandoned append may still be written.
pub(super) async fn preset(
    State(state): State<WebState>,
    Path(id): Path<String>,
    user: CurrentUser,
) -> Result<Response, Answer> {
    let services = Services::of(&state, &user).map_err(Refusal::status)?;
    let locale = user.locale();
    let store = saved::store(services.fleet());
    let shown = store
        .list(user.role())
        .map_err(|error| Answer::from(errors::internal(&error, fragment_shell(locale))))?
        .into_iter()
        .find(|preset| preset.id == id)
        .ok_or_else(|| Answer::from(StatusCode::NOT_FOUND.into_response()))?;
    let audit = shown.source.router_id.as_deref().map_or_else(
        || Audit::new("web.preset_reveal", id.clone()),
        |router| Audit::on_router("web.preset_reveal", router, id.clone()),
    );
    let revealed = (user.role().grants(Permission::RevealSecrets) && may_change(services, &shown))
        .then(|| store.get(user.role(), &id).ok())
        .flatten();
    let Some(full) = revealed else {
        audit.append(&state, &user, "forbidden").await;
        return Err(errors::response(Kind::Forbidden, fragment_shell(locale)).into());
    };
    let lines = full
        .lines
        .iter()
        .map(ToString::to_string)
        .filter(|line| secret(line))
        .map(SecretString::from)
        .collect::<Vec<_>>();
    audit
        .with_params(json!({ "lines": lines.len() }))
        .append(&state, &user, "shown")
        .await;
    Ok(errors::render(&Revealed::new(locale, full.name, lines)))
}

/// `POST /ui/presets/runs/{run}/reveal`: the previewed commands carrying a secret value.
///
/// # Errors
///
/// Answers the refusal of the run, the audited 403 without `RevealSecrets` on the
/// target, and 409 while the plan cannot be built.
// NOT cancel-safe: an abandoned append may still be written.
pub(super) async fn commands(
    State(state): State<WebState>,
    Path(id): Path<String>,
    Extension(runs): Extension<Arc<Wizards<Record>>>,
    user: CurrentUser,
) -> Result<Response, Answer> {
    let services = Services::of(&state, &user).map_err(Refusal::status)?;
    let visit = Visit::open(services, &runs, &id)
        .await
        .map_err(Refusal::status)?;
    let locale = user.locale();
    let target = visit.record().target().unwrap_or_default().to_owned();
    let audit = Audit::on_router("web.preset_run_reveal", &target, id);
    if !allowed(&user, &target, &[Permission::RevealSecrets]) {
        audit.append(&state, &user, "forbidden").await;
        return Err(errors::response(Kind::Forbidden, fragment_shell(locale)).into());
    }
    let conflict = || Answer::from(StatusCode::CONFLICT.into_response());
    let basis = Basis::of(&visit).await.map_err(|_problem| conflict())?;
    let request = basis
        .request(visit.record(), &state, services)
        .map_err(|_refused| conflict())?;
    let phases = &request.plan.phases;
    let lines = phases
        .additive
        .iter()
        .chain(&phases.prune)
        .chain(&phases.management)
        .map(PlannedLine::expose_command)
        .filter(|line| secret(line))
        .map(|line| SecretString::from(line.to_owned()))
        .collect::<Vec<_>>();
    let name = settings_text(visit.record(), locale);
    drop(visit);
    audit
        .with_params(json!({ "lines": lines.len() }))
        .append(&state, &user, "shown")
        .await;
    Ok(errors::render(&Revealed::new(locale, name, lines)))
}
