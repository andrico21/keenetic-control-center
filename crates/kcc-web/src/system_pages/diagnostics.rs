//! Diagnostics at `/ui/r/{router}/system/diagnostics`.
//!
//! Ping, traceroute, ARP ping and an iperf3 throughput test run by the router, each
//! started as a job whose lines arrive live through the job stream, with Stop.
//!
//! The domain describes the diagnostics as reads: whoever may read the router may run
//! them. The form is checked, then validated against the router's catalog, before the
//! router is asked anything; each start is audited with its field names.

use alloc::sync::Arc;

use askama::Template;
use axum::{
    Form,
    extract::{Path, State},
    http::HeaderMap,
    response::{IntoResponse as _, Response},
};
use kcc_catalog::HttpMethod;
use kcc_domain::diagnostics;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};
use serde_json::json;

use super::{
    diagnostic_form::Tool,
    jobs::JobPanel,
    shared::{Visit, value},
    tabs::{Tab, TabBar},
};
use crate::{
    WebState,
    authz::{CurrentSession, CurrentUser},
    errors,
    page::{Localize as _, Shell},
    page_kit::{
        action::Operation,
        audit::{Record, field_names},
        failure::issue_sentence,
        family::Family,
        outcome::{Failure, Outcome},
        request::Params,
        respond::Answer,
        submit::{self, Invalid, Submission},
    },
};

/// The diagnostic form, whose values that failed their check are named in the outcome
/// region.
struct InOutcome;

impl submit::Form for InOutcome {
    fn answer_invalid(self, invalid: Invalid, locale: Locale) -> Response {
        let problems = invalid
            .into_findings()
            .into_iter()
            .map(|(_field, rule)| tr(locale, rule, None))
            .collect();
        Outcome::invalid(Family::Changes, locale, problems).render(locale)
    }
}

/// The page.
#[derive(Template)]
#[template(path = "pages/system_diagnostics.html")]
struct Page {
    /// Page shell.
    shell: Shell,
    /// The system tabs.
    tabs: TabBar,
    /// Router profile id.
    router: String,
    /// Why the router cannot be used now.
    problem: Option<MessageKey>,
    /// Whether the job runner is attached.
    jobs: bool,
    /// The tools.
    tools: [Tool; 4],
}

localized!(Page);

/// `GET /ui/r/{router}/system/diagnostics`: the diagnostic form.
pub(crate) async fn page(
    State(state): State<WebState>,
    Path(router): Path<String>,
    headers: HeaderMap,
    current: CurrentSession,
    user: CurrentUser,
) -> Response {
    let (shell, reading) = match Visit::new(&headers, &current, &user)
        .open(&state, &router)
        .await
    {
        Ok(opened) => opened,
        Err(refusal) => return refusal.into_response(),
    };
    errors::render(&Page {
        shell,
        tabs: TabBar::new(router.clone(), Tab::Diagnostics),
        router,
        problem: reading.err(),
        jobs: state.advanced().jobs().is_some(),
        tools: Tool::ALL,
    })
}

/// `POST /ui/r/{router}/system/diagnostics`: checks the form, validates it against the
/// router's catalog and starts the diagnostic as a job; answers with its panel.
///
/// # Errors
///
/// Answers what the kit answers when the router or the permission is missing.
pub(crate) async fn start(
    State(state): State<WebState>,
    Path(router): Path<String>,
    user: CurrentUser,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let locale = user.locale();
    let Some(tool) = value(&pairs, "tool").and_then(Tool::from_name) else {
        let problem = tr(locale, keys::WEB_SYSTEM_DIAG_TOOL_ERROR, None);
        return Ok(Outcome::invalid(Family::Changes, locale, vec![problem]).render(locale));
    };
    let path = tool.kind().catalog_path();
    let opened = Operation::write(&diagnostics::DESCRIPTOR, tool.name(), tool.audit())
        .open(&state, &user, &router)
        .await?;
    let record = Record::on_router(tool.audit(), &router, path.to_owned());
    let params = Params::default();
    let (action, body) = Submission::new(opened, &params, InOutcome)
        .checked(|_params| tool.body(&pairs).map_err(|rule| Invalid::at("tool", rule)))
        .await?;
    let audited = record.with_params(json!({ "fields": field_names(&body) }));
    let domain = action.context().await?;
    let validated = match domain.catalog.validate(path, HttpMethod::Post, &body) {
        Ok(validated) => validated,
        Err(issues) => {
            audited.append(&state, &user, "validation_failed").await;
            let problems = issues
                .iter()
                .map(|issue| issue_sentence(locale, issue))
                .collect();
            return Ok(Outcome::invalid(Family::Changes, locale, problems).render(locale));
        }
    };
    let Some(jobs) = state.advanced().jobs().cloned() else {
        let failure = Failure::new(
            tr(locale, keys::WEB_EXPLORER_JOBS_UNAVAILABLE, None),
            "failed",
        );
        audited.append(&state, &user, failure.audit()).await;
        return Ok(Outcome::failed(failure).render(locale));
    };
    let events = jobs.subscribe();
    let started = diagnostics::start_job(
        &jobs,
        router.clone(),
        Arc::clone(&domain.client),
        tool.kind(),
        validated.value,
    )
    .await;
    match started {
        Ok(id) => {
            state
                .advanced()
                .feeds()
                .follow(Arc::clone(&jobs), events, id.clone());
            audited.append(&state, &user, "started").await;
            Ok(JobPanel::new(locale, &router, id)
                .titled(tool.label())
                .answer())
        }
        Err(error) => {
            tracing::warn!(%error, "diagnostic did not start");
            let failure = Failure::new(tr(locale, Family::Changes.failed(), None), "failed");
            audited.append(&state, &user, failure.audit()).await;
            Ok(Outcome::failed(failure).render(locale))
        }
    }
}
