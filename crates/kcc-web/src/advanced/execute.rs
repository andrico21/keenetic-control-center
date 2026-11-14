//! `POST /ui/r/{router}/explorer/execute`: runs the command of the explorer form.
//!
//! The form is validated against the router's catalog before anything is sent. A read
//! needs `Read`; a change needs `RawRci` and a confirmation; a management change also
//! needs `Destructive` (kcc arms the fail-safe timer) and a destructive one the typed
//! router name. Reads use the shared client, changes the change workflow, and reading
//! commands the catalog marks as background work run as jobs (background work that
//! changes the router is refused unsent). Every execution is audited.

use axum::{
    Form,
    extract::{Path, State},
    response::Response,
};
use kcc_app::workflow::BatchItem;
use kcc_catalog::Risk;
use serde_json::json;

use super::{
    deliver::{Sender, raw_batch},
    jobs,
    lookup::facts_for,
    outcome::Reply,
    request::{self, Delivery},
};
use crate::{
    WebState,
    authz::{CurrentSession, CurrentUser},
    errors::refusal,
    page_kit::{
        audit::{Record, field_names},
        confirm::{Confirmation, Resubmit},
        family::Family,
        gate::{allowed, command_permissions},
        respond,
        stakes::Stakes,
    },
};

/// `POST /ui/r/{router}/explorer/execute`: validates and runs the explorer form.
// NOT cancel-safe: a confirmed write may apply before cancellation.
pub(crate) async fn execute(
    State(state): State<WebState>,
    Path(router): Path<String>,
    current: CurrentSession,
    user: CurrentUser,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Response {
    let (target, facts) = match facts_for(&state, &user, &router).await {
        Ok(found) => found,
        Err(response) => return *response,
    };
    let locale = user.locale();
    let pending = Record::on_router(
        "web.explorer_execute",
        &router,
        request::path_of(&pairs).to_owned(),
    );
    let built = match request::build(facts.catalog(), &pairs) {
        Ok(found) => found,
        Err(problems) => {
            pending.append(&state, &user, "validation_failed").await;
            return Reply::invalid(locale, &problems).render(locale);
        }
    };
    let params = json!({
        "fields": field_names(built.body()),
        "background": built.delivery() == Delivery::Background,
    });
    let audit = pending.with_params(params.clone());
    let risk = built.risk();
    let needed = command_permissions(risk);
    if !allowed(&user, &router, &needed) {
        audit.append(&state, &user, "forbidden").await;
        let missing = refusal::missing(&user, &router, &needed);
        return refusal::refused(locale, &missing, "#explorer-result");
    }
    let confirmation = Confirmation::from_pairs(&pairs);
    let stakes = Stakes::of(built.validated());
    if let Some(prompt) = Family::Commands.ask(stakes, &confirmation, &router) {
        let resubmit = Resubmit::new(
            format!("/ui/r/{router}/explorer/execute"),
            "#explorer-result",
        )
        .with_include("#explorer-form");
        return prompt
            .with_persists(built.validated().persists_immediately)
            .with_persisted_paths(built.validated().persisted_paths.clone())
            .render(resubmit, locale);
    }
    let session = current.stream_key();
    let dispatch = Sender::new(&state, &user, &session).to(target, &facts);
    let outcome = match built.delivery() {
        Delivery::Background => match jobs::start(&state, target, &user, &built).await {
            Ok(panel) => Reply::job(locale, panel),
            Err(failure) => Reply::failed(failure),
        },
        Delivery::Read => dispatch.read_root(&built.root()).await,
        Delivery::Batch => {
            let item = (BatchItem::new(built.root()), built.validated().clone());
            dispatch.change(risk, raw_batch(vec![item], params)).await
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
