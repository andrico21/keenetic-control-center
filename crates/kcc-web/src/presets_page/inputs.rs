//! Step 5: the passwords of router users whose hashes are bound to the source's realm,
//! write-only (an empty field keeps one already typed); then the plan is built and the
//! preview opens.

use alloc::{collections::BTreeSet, sync::Arc};
use core::fmt::Display;

use askama::Template;
use axum::{
    Extension, Form,
    extract::{Path, State},
    response::Response,
};
use fluent_bundle::FluentArgs;
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_migrate::{
    presets::{apply::PresetApplyError, plan::PresetPlanItem},
    rules::Disposition,
};
use secrecy::SecretString;
use serde_json::json;

use super::{
    access::Visit,
    fates::blocking,
    plan::{Basis, Refused, plan_problem},
    record::Record,
    steps::Step,
    target::problem_text,
};
use crate::{
    WebState,
    authz::CurrentUser,
    errors::{self, Kind},
    page::{Localize as _, Shell},
    page_kit::{
        audit::Record as Audit,
        context::{Refusal, fragment_shell},
        request::last,
        respond::{self, Answer},
    },
    wizard::{flow::Flow as _, screen, service::Wizards, services::Services},
};

/// The longest password kcc passes to a router, in characters.
const PASSWORD_MAX: usize = 256;

/// The step's panel.
#[derive(Template)]
#[template(path = "partials/presets_inputs.html")]
pub(super) struct Panel {
    /// Locale carrier.
    shell: Shell,
    /// Run id.
    id: String,
    /// One password field per user: user, field name, whether one is typed, error.
    passwords: Vec<(String, String, bool, String)>,
    /// What still blocks the plan.
    blocked: Vec<String>,
    /// Why the inputs cannot be shown.
    problem: String,
}

localized!(Panel);

impl Panel {
    /// The inputs of `visit`, with `errors` beside the users' fields.
    // cancel-safe: reads only.
    pub(super) async fn new(visit: &Visit<'_>, errors: &[(String, String)]) -> Self {
        let locale = visit.services().user().locale();
        let mut panel = Self {
            shell: fragment_shell(locale),
            id: visit.record().id().to_owned(),
            passwords: Vec::new(),
            blocked: Vec::new(),
            problem: String::new(),
        };
        let users = match Basis::of(visit).await {
            Ok(basis) => basis
                .users(visit.record())
                .map_err(|error| problem_text(&plan_problem(&error), locale)),
            Err(problem) => Err(problem_text(&problem, locale)),
        };
        match users {
            Ok(found) => {
                panel.passwords = found
                    .into_iter()
                    .enumerate()
                    .map(|(index, user)| {
                        let error = errors
                            .iter()
                            .find(|(name, _)| *name == user)
                            .map_or_else(String::new, |(_, text)| text.clone());
                        let stored = visit.record().passwords().contains(&user);
                        (user, format!("password-{index}"), stored, error)
                    })
                    .collect();
            }
            Err(text) => panel.problem = text,
        }
        panel
    }
}

/// `POST /ui/presets/runs/{run}/inputs`: checks and seals the passwords, builds the plan
/// and opens its preview.
///
/// # Errors
///
/// Answers the refusal of the run, and the panel with its errors (422).
// NOT cancel-safe: an abandoned append may still be written.
#[expect(
    clippy::significant_drop_tightening,
    reason = "each answer is built from the record, which lives in the visit holding the turn"
)]
pub(super) async fn submit(
    State(state): State<WebState>,
    Path(id): Path<String>,
    Extension(runs): Extension<Arc<Wizards<Record>>>,
    user: CurrentUser,
    Form(form): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let services = Services::of(&state, &user).map_err(Refusal::status)?;
    let mut visit = Visit::open(services, &runs, &id)
        .await
        .map_err(Refusal::status)?;
    if visit.record().step() != Step::Inputs {
        return Ok(screen::moved(visit.record()));
    }
    let locale = user.locale();
    let internal =
        |error: &dyn Display| Answer::from(errors::internal(error, fragment_shell(locale)));
    let Ok(mut basis) = Basis::of(&visit).await else {
        return Err(respond::unprocessable(&Panel::new(&visit, &[]).await).into());
    };
    let Ok(users) = basis.users(visit.record()) else {
        return Err(respond::unprocessable(&Panel::new(&visit, &[]).await).into());
    };
    let mut passwords = visit.passwords().map_err(|error| internal(&error))?;
    let mut refused = Vec::new();
    for (index, name) in users.iter().enumerate() {
        let field = format!("password-{index}");
        let typed = last(&form, &field).unwrap_or_default();
        let error = if typed.is_empty() {
            (!passwords.contains_key(name)).then_some(keys::WEB_MIGRATE_INPUTS_PASSWORD_MISSING)
        } else if typed.chars().count() > PASSWORD_MAX || typed.chars().any(char::is_control) {
            Some(keys::WEB_MIGRATE_INPUTS_PASSWORD_INVALID)
        } else {
            drop(passwords.insert(name.clone(), SecretString::from(typed.to_owned())));
            None
        };
        if let Some(key) = error {
            refused.push((name.clone(), tr(locale, key, None)));
        }
    }
    if !refused.is_empty() {
        return Err(respond::unprocessable(&Panel::new(&visit, &refused).await).into());
    }
    passwords.retain(|name, _| users.contains(name));
    visit
        .seal_passwords(&passwords)
        .map_err(|error| internal(&error))?;
    visit
        .record_mut()
        .set_passwords(passwords.keys().cloned().collect::<BTreeSet<_>>());
    basis.set_passwords(passwords);
    let kept = basis.kept(visit.record());
    match basis.request(visit.record(), &state, services) {
        Ok(request) => {
            visit
                .record_mut()
                .preview_ready(request.plan.plan_id.clone());
            visit.save().map_err(|error| internal(&error))?;
            let record = visit.record();
            Audit::on_router("web.preset_inputs", record.target().unwrap_or_default(), id)
                .with_params(json!({ "users": record.passwords().len() }))
                .append(&state, &user, "saved")
                .await;
            Ok(screen::moved(visit.record()))
        }
        Err(Refused::Apply(PresetApplyError::PlanNotReady)) => {
            visit.save().map_err(|error| internal(&error))?;
            let mut panel = Panel::new(&visit, &[]).await;
            panel.blocked = kept.map_or_default(|plan| blocked(&plan.items, &visit, locale));
            Err(respond::unprocessable(&panel).into())
        }
        Err(Refused::Plan(error)) => {
            let mut panel = Panel::new(&visit, &[]).await;
            panel.problem = problem_text(&plan_problem(&error), locale);
            Err(respond::unprocessable(&panel).into())
        }
        Err(Refused::Apply(PresetApplyError::Forbidden)) => {
            Err(errors::response(Kind::Forbidden, fragment_shell(locale)).into())
        }
        Err(Refused::Apply(PresetApplyError::InvalidPlan | _)) => {
            let mut panel = Panel::new(&visit, &[]).await;
            panel.problem = tr(locale, keys::WEB_MIGRATE_PROBLEM_PLAN, None);
            Err(respond::unprocessable(&panel).into())
        }
    }
}

/// The settings among `items` that still block the plan, each with its number.
fn blocked(items: &[PresetPlanItem], visit: &Visit<'_>, locale: Locale) -> Vec<String> {
    items
        .iter()
        .filter(|item| {
            matches!(
                item.disposition,
                Disposition::NeedsInput | Disposition::Conflict
            )
        })
        .map(|item| {
            let mut args = FluentArgs::new();
            args.set("line", item.index.saturating_add(1).to_string());
            args.set("value", blocking(item, visit.record(), locale));
            tr(locale, keys::WEB_MIGRATE_INPUTS_BLOCKED_ITEM, Some(&args))
        })
        .collect()
}
