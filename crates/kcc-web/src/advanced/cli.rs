//! The CLI console at `/ui/r/{router}/console/cli` (route table: `RawRci`).
//!
//! One CLI line is mapped to its catalog command by its leading words and sent with
//! `parse`. A line with no catalog command is refused, unless an administrator explicitly
//! sends it without validation (`RawRci` plus `ManageRouters`), which is audited as such.

use core::fmt;

use askama::Template;
use axum::{
    Form,
    extract::{Path, State},
    http::HeaderMap,
    response::Response,
};
use fluent_bundle::FluentArgs;
use kcc_app::{permissions::Permission, workflow::CliCommand as ValidatedCli};
use kcc_catalog::{Catalog, RawAuthorization, Risk, ValidatedRequest, ValidationIssue};
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
};
use secrecy::{ExposeSecret as _, SecretString};
use serde::Deserialize;
use serde_json::json;

use super::{
    check::{Problem, Report, from_issues},
    deliver::{Sender, raw_cli},
    lookup::{catalog_note, facts_for, problem},
    outcome::Reply,
};
use crate::{
    WebState,
    authz::{CurrentSession, CurrentUser},
    errors::{self, refusal},
    nav::Section,
    page::{Localize as _, Shell},
    page_kit::{
        audit::Record,
        confirm::{Confirmation, Resubmit, Stakes},
        context::{self, Caller},
        family::Family,
        gate::{allowed, command_permissions},
        respond,
    },
};

/// Longest line read from the console.
const MAX_LINE: usize = 1024;

/// The console form.
#[derive(Default, Deserialize)]
pub(crate) struct CliForm {
    /// The CLI line; it can carry a router secret.
    #[serde(default)]
    line: SecretString,
    /// Checked to send a line outside the catalog.
    #[serde(default)]
    unvalidated: Option<String>,
    /// Set by the confirmation dialog.
    #[serde(default)]
    confirm: Option<String>,
    /// Router name typed into the confirmation dialog.
    #[serde(default)]
    confirm_name: Option<String>,
}

impl fmt::Debug for CliForm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CliForm")
            .field("unvalidated", &self.unvalidated)
            .field("confirm", &self.confirm)
            .field("confirm_name", &self.confirm_name)
            .finish_non_exhaustive()
    }
}

/// The console page.
#[derive(Template)]
#[template(path = "pages/console_cli.html")]
struct Page {
    /// Page shell.
    shell: Shell,
    /// Router profile id.
    router: String,
    /// Localized catalog line.
    catalog_note: String,
    /// Why no catalog is available.
    problem: Option<MessageKey>,
    /// Whether the user may send lines without validation.
    can_escape: bool,
}

localized!(Page);

/// `GET /ui/r/{router}/console/cli`: the console.
pub(crate) async fn page(
    State(state): State<WebState>,
    Path(router): Path<String>,
    headers: HeaderMap,
    current: CurrentSession,
    user: CurrentUser,
) -> Response {
    let shell = Caller::new(&headers, &current, &user)
        .shell(&state, Section::Advanced, Some(&router))
        .await;
    let target = match context::target(&state, &user, &router).await {
        Ok(found) => found,
        Err(refusal) => return refusal.page(shell),
    };
    let (catalog_note, problem) = match target.facts(&state).await {
        Ok(facts) => (catalog_note(&facts, user.locale()), None),
        Err(error) => (String::new(), Some(problem(error))),
    };
    errors::render(&Page {
        shell,
        can_escape: escape_allowed(&user, &router),
        router,
        catalog_note,
        problem,
    })
}

/// `POST /ui/r/{router}/console/cli/check`: the command the line maps to; nothing is sent.
// cancel-safe: only router facts are read before rendering.
pub(crate) async fn validate(
    State(state): State<WebState>,
    Path(router): Path<String>,
    user: CurrentUser,
    Form(form): Form<CliForm>,
) -> Response {
    let (_, facts) = match facts_for(&state, &user, &router).await {
        Ok(found) => found,
        Err(response) => return *response,
    };
    let locale = user.locale();
    match check(facts.catalog(), &form, authorization(&user, &router, &form)) {
        Ok(validated) => {
            let summary = if validated.unvalidated {
                tr(locale, keys::WEB_CONSOLE_MATCHED_RAW, None)
            } else {
                let mut args = FluentArgs::new();
                args.set("path", validated.path.clone());
                tr(locale, keys::WEB_CONSOLE_MATCHED, Some(&args))
            };
            Report::valid(summary, validated.risk)
                .with_persists(validated.persists_immediately)
                .with_persisted_paths(validated.persisted_paths.clone())
                .with_explore(
                    &router,
                    (!validated.unvalidated).then_some(validated.path.as_str()),
                )
                .respond(locale)
        }
        Err(problems) => Report::invalid(locale, &problems).respond(locale),
    }
}

/// `POST /ui/r/{router}/console/cli/send`: validates again and sends the line.
// NOT cancel-safe: a confirmed write may apply before cancellation.
pub(crate) async fn send(
    State(state): State<WebState>,
    Path(router): Path<String>,
    current: CurrentSession,
    user: CurrentUser,
    Form(form): Form<CliForm>,
) -> Response {
    let (target, facts) = match facts_for(&state, &user, &router).await {
        Ok(found) => found,
        Err(response) => return *response,
    };
    let locale = user.locale();
    let validated = match check(facts.catalog(), &form, authorization(&user, &router, &form)) {
        Ok(found) => found,
        Err(problems) => {
            Record::on_router("web.console_cli", &router, "unmatched".to_owned())
                .append(&state, &user, "validation_failed")
                .await;
            return respond::retarget(
                Reply::invalid(locale, &problems).render(locale),
                "#cli-check",
            );
        }
    };
    let risk = validated.risk;
    let label = if validated.unvalidated {
        "unvalidated".to_owned()
    } else {
        validated.path.clone()
    };
    let params = json!({
        "unvalidated": validated.unvalidated,
        "words": form.line.expose_secret().split_whitespace().count(),
    });
    let audit = Record::on_router("web.console_cli", &router, label).with_params(params.clone());
    let mut needed = vec![Permission::RawRci];
    needed.extend_from_slice(&command_permissions(risk));
    if validated.unvalidated {
        needed.push(Permission::ManageRouters);
    }
    if !allowed(&user, &router, &needed) {
        audit.append(&state, &user, "forbidden").await;
        let missing = refusal::missing(&user, &router, &needed);
        return refusal::refused(locale, &missing, "#cli-result");
    }
    let confirmation = Confirmation::new(form.confirm.as_deref(), form.confirm_name.as_deref());
    if let Some(prompt) = Stakes::of(&validated).ask(Family::Commands, &confirmation, &router) {
        let resubmit = Resubmit::new(format!("/ui/r/{router}/console/cli/send"), "#cli-result")
            .with_include("#cli-form");
        return prompt
            .with_persists(validated.persists_immediately)
            .with_persisted_paths(validated.persisted_paths.clone())
            .render(resubmit, locale);
    }
    let session = current.stream_key();
    let dispatch = Sender::new(&state, &user, &session).to(target, &facts);
    let line = form.line.expose_secret().trim().to_owned();
    let outcome = if risk == Risk::Read {
        dispatch
            .read_with(async move |client| client.parse(&line).await)
            .await
    } else {
        match ValidatedCli::new(line, validated) {
            Ok(command) => dispatch.change(risk, raw_cli(vec![command], params)).await,
            Err(_error) => Reply::invalid(
                locale,
                &from_issues(vec![ValidationIssue::InvalidCliSyntax]),
            ),
        }
    };
    audit.append_outcome(&state, &user, outcome.outcome()).await;
    let response = outcome.render(locale);
    if risk == Risk::Read {
        response
    } else {
        respond::close_dialog(response)
    }
}

/// Validates one CLI line against `catalog`.
///
/// # Errors
///
/// Returns every problem found; nothing may be sent then.
fn check(
    catalog: &Catalog,
    form: &CliForm,
    authorization: RawAuthorization,
) -> Result<ValidatedRequest, Vec<Problem>> {
    let line = form.line.expose_secret().trim();
    if line.is_empty() || line.len() > MAX_LINE {
        return Err(vec![Problem::Length]);
    }
    catalog
        .validate_cli(line, authorization)
        .map_err(from_issues)
}

/// The raw-escape authorization of a form: granted only when the box is checked and the
/// user holds `RawRci` and `ManageRouters` on the router.
fn authorization(user: &CurrentUser, router: &str, form: &CliForm) -> RawAuthorization {
    let mut authorization = RawAuthorization::default();
    if form.unvalidated.as_deref() == Some("on") && escape_allowed(user, router) {
        authorization.raw_rci = true;
        authorization.admin_manage_routers = true;
    }
    authorization
}

/// Whether `user` may send lines outside the catalog to `router`.
fn escape_allowed(user: &CurrentUser, router: &str) -> bool {
    allowed(
        user,
        router,
        &[Permission::RawRci, Permission::ManageRouters],
    )
}
