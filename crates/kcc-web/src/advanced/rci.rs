//! The RCI console at `/ui/r/{router}/console/rci` (route table: `RawRci`).
//!
//! A method, a catalog path and a JSON body are checked against the router's catalog
//! while typing and again before anything is sent. At the root endpoint a list of objects
//! is one batch.

use askama::Template;
use axum::{
    Form,
    extract::{Path, State},
    http::HeaderMap,
    response::Response,
};
use fluent_bundle::FluentArgs;
use kcc_app::{
    permissions::Permission,
    workflow::{BatchItem, DeleteRequest},
};
use kcc_catalog::{HttpMethod, Risk};
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
};
use kcc_rci::{RciError, RciPath};
use serde_json::{Value, json};

use super::{
    check::{Report, root_object},
    deliver::{Dispatch, Sender, raw_batch},
    lookup::{catalog_note, facts_for, problem},
    outcome::Reply,
    rci_check::{Checked, RciForm, check, path_segments},
};
use crate::{
    WebState,
    authz::{CurrentSession, CurrentUser},
    errors::{self, Kind},
    nav::Section,
    page::{Localize, Shell},
    page_kit::{
        audit::Record,
        change::Change,
        confirm::{Gate, Prompt, Resubmit},
        context::{self, Caller, fragment_shell},
        family::Family,
        gate::{allowed, command_permissions},
        respond,
    },
};

/// The console page.
#[derive(Template)]
#[template(path = "pages/console_rci.html")]
struct Page {
    /// Page shell.
    shell: Shell,
    /// Router profile id.
    router: String,
    /// Localized catalog line.
    catalog_note: String,
    /// Why no catalog is available.
    problem: Option<MessageKey>,
    /// The method choices.
    methods: [&'static str; 3],
}

impl Localize for Page {
    fn shell(&self) -> &Shell {
        &self.shell
    }
}

/// `GET /ui/r/{router}/console/rci`: the console.
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
        router,
        catalog_note,
        problem,
        methods: ["POST", "GET", "DELETE"],
    })
}

/// `POST /ui/r/{router}/console/rci/check`: the validation result; nothing is sent.
pub(crate) async fn validate(
    State(state): State<WebState>,
    Path(router): Path<String>,
    user: CurrentUser,
    Form(form): Form<RciForm>,
) -> Response {
    let (_, facts) = match facts_for(&state, &user, &router).await {
        Ok(found) => found,
        Err(response) => return *response,
    };
    let locale = user.locale();
    match check(facts.catalog(), &form) {
        Ok(checked) => {
            let mut args = FluentArgs::new();
            args.set("count", checked.count());
            Report::valid(
                tr(locale, keys::WEB_CONSOLE_VALID, Some(&args)),
                checked.risk(),
            )
            .with_explore(&router, checked.explore())
            .respond(locale)
        }
        Err(problems) => Report::invalid(locale, &problems).respond(locale),
    }
}

/// `POST /ui/r/{router}/console/rci/send`: validates again and sends.
pub(crate) async fn send(
    State(state): State<WebState>,
    Path(router): Path<String>,
    current: CurrentSession,
    user: CurrentUser,
    Form(form): Form<RciForm>,
) -> Response {
    let (target, facts) = match facts_for(&state, &user, &router).await {
        Ok(found) => found,
        Err(response) => return *response,
    };
    let locale = user.locale();
    let checked = match check(facts.catalog(), &form) {
        Ok(found) => found,
        Err(problems) => {
            Record::on_router("web.console_rci", &router, form.label())
                .append(&state, &user, "validation_failed")
                .await;
            return respond::retarget(
                Reply::invalid(locale, &problems).render(locale),
                "#rci-check",
            );
        }
    };
    let risk = checked.risk();
    let params = json!({ "method": form.method_name(), "items": checked.count(), "fields": checked.fields() });
    let audit =
        Record::on_router("web.console_rci", &router, form.label()).with_params(params.clone());
    if !allowed(&user, &router, &[Permission::RawRci])
        || !allowed(&user, &router, command_permissions(risk))
    {
        audit.append(&state, &user, "forbidden").await;
        return errors::response(Kind::Forbidden, fragment_shell(locale));
    }
    let confirmation = form.confirmation();
    if let Gate::Ask { wrong_name } = Family::Commands.gate(risk, &confirmation, &router) {
        let resubmit = Resubmit::new(format!("/ui/r/{router}/console/rci/send"), "#rci-result")
            .with_include("#rci-form");
        return Prompt::new(Family::Commands, risk, &router)
            .with_wrong_name(wrong_name)
            .render(resubmit, locale);
    }
    let session = current.stream_key();
    let dispatch = Sender::new(&state, &user, &session).to(target, &facts);
    let outcome = run(dispatch, checked, params).await;
    audit.append(&state, &user, outcome.audit()).await;
    let response = outcome.render(locale);
    if risk == Risk::Read {
        response
    } else {
        respond::close_dialog(response)
    }
}

/// Sends a checked console request: reads through the shared client, everything else
/// through the change workflow.
// NOT cancel-safe: see `Dispatch::change`.
async fn run(dispatch: Dispatch<'_>, checked: Checked, params: Value) -> Reply {
    let risk = checked.risk();
    match checked {
        Checked::Path {
            method: HttpMethod::Get,
            validated,
            show,
        } => {
            let words = path_segments(&validated.path);
            dispatch
                .read_with(async move |client| {
                    let resource =
                        RciPath::from_segments(&words).map_err(|_error| RciError::Validation)?;
                    if show {
                        client.show(&resource, &validated.value).await
                    } else {
                        client.get(&resource, &validated.value).await
                    }
                })
                .await
        }
        Checked::Path {
            method: HttpMethod::Delete,
            validated,
            show: _,
        } => {
            let request = DeleteRequest::new(
                validated.path.clone(),
                path_segments(&validated.path),
                validated.value,
                Vec::new(),
                Permission::RawRci,
                params.clone(),
            );
            dispatch.change(risk, Change::Delete(request)).await
        }
        Checked::Path {
            method: _,
            validated,
            show: _,
        } => {
            let root = root_object(&validated.path, validated.value.clone());
            if risk == Risk::Read {
                dispatch.read_root(&root).await
            } else {
                dispatch
                    .change(
                        risk,
                        raw_batch(vec![BatchItem::new(root, validated)], params),
                    )
                    .await
            }
        }
        Checked::Root { items, risk: _ } => {
            if risk == Risk::Read {
                dispatch
                    .read_batch(
                        items
                            .into_iter()
                            .map(|item| item.value.redacted().clone())
                            .collect(),
                    )
                    .await
            } else {
                dispatch.change(risk, raw_batch(items, params)).await
            }
        }
    }
}
