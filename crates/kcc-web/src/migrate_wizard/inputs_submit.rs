//! Step 5's submit: every needed input checked, the passwords sealed, and the plan built
//! with them; a plan that builds opens the preview.

use alloc::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
use core::{fmt::Display, str::FromStr as _};

use axum::{
    Extension, Form,
    extract::{Path, State},
    response::Response,
};
use fluent_bundle::FluentArgs;
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_migrate::planner::PlanError;
use kcc_rci::RouterUrl;
use secrecy::SecretString;
use serde_json::json;

use super::{
    access::{Migration as _, Visit},
    inputs::{Panel, Shown},
    kinds::{Inputs, Step},
    needs::Needs,
    plan::{Built, Classified},
    reasons::reason,
    record::Record,
};
use crate::{
    WebState,
    authz::CurrentUser,
    errors,
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

/// `POST /ui/migrate/{id}/inputs`: checks the inputs, seals the passwords, builds the plan
/// and opens its preview.
///
/// # Errors
///
/// Answers the refusal of the migration, and the panel with its errors (422).
#[expect(
    clippy::significant_drop_tightening,
    reason = "each answer is built from the record, which lives in the visit holding the turn"
)]
pub(super) async fn submit(
    State(state): State<WebState>,
    Path(id): Path<String>,
    Extension(wizards): Extension<Arc<Wizards<Record>>>,
    user: CurrentUser,
    Form(form): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let services = Services::of(&state, &user).map_err(Refusal::status)?;
    let mut visit = Visit::open(services, &wizards, &id)
        .await
        .map_err(Refusal::status)?;
    if visit.record().step() != Step::Inputs {
        return Ok(screen::moved(visit.record()));
    }
    let locale = user.locale();
    let internal =
        |error: &dyn Display| Answer::from(errors::internal(error, fragment_shell(locale)));
    let Ok(analysis) = visit.analysis().await else {
        return Err(respond::unprocessable(&Panel::new(&visit, Shown::default()).await).into());
    };
    let mut passwords = visit.passwords().map_err(|error| internal(&error))?;
    let classified =
        Classified::new(&analysis, visit.record(), &passwords).map_err(|error| internal(&error))?;
    let needs = Needs::of(&analysis, &classified, visit.record());
    let (checked_inputs, shown) = checked(&needs, &form, &mut passwords, locale);
    let Some(inputs) = checked_inputs else {
        return Err(respond::unprocessable(&Panel::new(&visit, shown).await).into());
    };
    visit
        .seal_passwords(&passwords)
        .map_err(|error| internal(&error))?;
    visit.record_mut().set_inputs(inputs);
    let built = Built::new(&analysis, visit.record(), &passwords);
    visit.save().map_err(|error| internal(&error))?;
    match built {
        Ok(found) => {
            visit
                .record_mut()
                .preview_ready(found.plan().plan_id.clone());
            visit.save().map_err(|error| internal(&error))?;
            let record = visit.record();
            Audit::on_router(
                "web.migrate_inputs",
                record.target().unwrap_or_default(),
                id,
            )
            .with_params(json!({
                "users": record.passwords().len(),
                "components": record.components(),
                "reconnect": record.reconnect_url().is_some(),
                "agreements": record.agreements().keys().collect::<Vec<_>>(),
            }))
            .append(&state, &user, "saved")
            .await;
            Ok(screen::moved(visit.record()))
        }
        Err(PlanError::PlanBlocked { items }) => {
            let blocked = items
                .iter()
                .map(|item| {
                    let mut args = FluentArgs::new();
                    args.set("line", item.line_no.to_string());
                    args.set("value", reason(item, None, locale));
                    tr(locale, keys::WEB_MIGRATE_INPUTS_BLOCKED_ITEM, Some(&args))
                })
                .collect();
            let panel = Panel::new(&visit, Shown::default().blocked(blocked)).await;
            Err(respond::unprocessable(&panel).into())
        }
        Err(error) => Err(internal(&error)),
    }
}

/// The inputs `form` gives for `needs`, with the typed passwords merged into
/// `passwords`; `None` and what to show again when any input is missing or invalid.
fn checked(
    needs: &Needs,
    form: &[(String, String)],
    passwords: &mut BTreeMap<String, SecretString>,
    locale: Locale,
) -> (Option<Inputs>, Shown) {
    let value = |field: &str| last(form, field);
    let values = |field: &str| {
        form.iter()
            .filter(|(name, _)| name == field)
            .map(|(_, typed)| typed.clone())
            .collect::<Vec<_>>()
    };
    let mut shown = Shown::default();
    let mut failed = false;
    for (index, user) in needs.users().iter().enumerate() {
        let typed = value(&format!("password-{index}")).unwrap_or_default();
        let error = if value(&format!("user-{index}")) != Some(user.as_str()) {
            Some(keys::WEB_MIGRATE_INPUTS_PASSWORD_USER)
        } else if typed.is_empty() {
            (!passwords.contains_key(user)).then_some(keys::WEB_MIGRATE_INPUTS_PASSWORD_MISSING)
        } else if typed.chars().count() > PASSWORD_MAX || typed.chars().any(char::is_control) {
            Some(keys::WEB_MIGRATE_INPUTS_PASSWORD_INVALID)
        } else {
            drop(passwords.insert(user.clone(), SecretString::from(typed.to_owned())));
            None
        };
        if let Some(key) = error {
            failed = true;
            shown = shown.password_error(user, tr(locale, key, None));
        }
    }
    passwords.retain(|user, _| needs.users().contains(user));
    let checked = values("component")
        .into_iter()
        .filter(|name| needs.components().contains_key(name))
        .collect::<Vec<_>>();
    let missing = needs
        .components()
        .keys()
        .filter(|name| !checked.contains(name))
        .cloned()
        .collect::<Vec<_>>();
    let component_error = if missing.is_empty() {
        String::new()
    } else {
        failed = true;
        let mut args = FluentArgs::new();
        args.set("value", missing.join(", "));
        tr(
            locale,
            keys::WEB_MIGRATE_INPUTS_COMPONENT_MISSING,
            Some(&args),
        )
    };
    shown = shown.components(checked.clone(), component_error);
    let reconnect = if needs.reconnect() {
        let typed = value("reconnect_url").unwrap_or_default().trim().to_owned();
        match RouterUrl::from_str(&typed) {
            Ok(url) => Some(url.as_str().to_owned()),
            Err(_invalid) => {
                failed = true;
                let error = tr(locale, keys::WEB_MIGRATE_INPUTS_RECONNECT_ERROR, None);
                shown = shown.reconnect(typed, error);
                None
            }
        }
    } else {
        None
    };
    let accepted = values("agreement");
    let agreements = needs
        .agreements()
        .iter()
        .filter(|(name, _)| accepted.iter().any(|chosen| chosen == name))
        .map(|(name, text)| ((*name).to_owned(), text.clone()))
        .collect::<BTreeMap<_, _>>();
    if agreements.len() < needs.agreements().len() {
        failed = true;
        let error = tr(locale, keys::WEB_MIGRATE_INPUTS_ACCEPT_REQUIRED, None);
        shown = shown.agreements(accepted, error);
    }
    if failed {
        return (None, shown);
    }
    let inputs = Inputs::default()
        .with_components(checked.into_iter().collect())
        .with_reconnect_url(reconnect)
        .with_agreements(agreements)
        .with_passwords(passwords.keys().cloned().collect::<BTreeSet<_>>());
    (Some(inputs), shown)
}
