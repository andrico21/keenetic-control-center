//! `POST /ui/r/{router}/explorer/execute`: runs the command of the explorer form.
//!
//! The form is validated against the router's catalog before anything is sent. A read
//! needs `Read`; a change needs `RawRci` and a confirmation; a management change also
//! needs `Destructive` (kcc arms the fail-safe timer) and a destructive one the typed
//! router name. Reads use the shared client, changes the change workflow, and commands
//! the catalog marks as background work run as jobs. Every execution is audited.

use axum::{
    Form,
    extract::{Path, State},
    response::Response,
};
use kcc_app::workflow::BatchItem;
use kcc_catalog::Risk;
use serde_json::json;

use super::{
    apply::Change,
    context::{Execution, allowed, field_names},
    deliver::Sender,
    gate::{self, Confirmation, Gate, Prompt, Resubmit},
    jobs,
    lookup::facts_for,
    outcome::Outcome,
    request::{self, Delivery},
};
use crate::{
    WebState,
    authz::{CurrentSession, CurrentUser},
    errors::{self, Kind},
    page::{Shell, Theme},
};

/// `POST /ui/r/{router}/explorer/execute`: validates and runs the explorer form.
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
    let pending = Execution::new(
        "web.explorer_execute",
        &router,
        request::path_of(&pairs).to_owned(),
    );
    let built = match request::build(facts.catalog(), &pairs) {
        Ok(found) => found,
        Err(problems) => {
            pending.record(&state, &user, "validation_failed").await;
            return Outcome::invalid(locale, &problems).render(locale);
        }
    };
    let params = json!({
        "fields": field_names(built.body()),
        "background": built.delivery() == Delivery::Background,
    });
    let audit = pending.with_params(params.clone());
    let risk = built.risk();
    if !allowed(&user, &router, gate::permissions(risk)) {
        audit.record(&state, &user, "forbidden").await;
        return errors::response(Kind::Forbidden, Shell::new(locale, Theme::System));
    }
    let confirmation = Confirmation::from_pairs(&pairs);
    if let Gate::Ask { wrong_name } = gate::gate(risk, &confirmation, &router) {
        let resubmit = Resubmit::new(
            format!("/ui/r/{router}/explorer/execute"),
            "#explorer-form",
            "#explorer-result",
        );
        return Prompt::new(risk, &router, resubmit)
            .with_wrong_name(wrong_name)
            .render(locale);
    }
    let session = current.stream_key();
    let dispatch = Sender::new(&state, &user, &session).to(target, &facts);
    let outcome = match built.delivery() {
        Delivery::Background => match jobs::start(&state, target, &user, &built).await {
            Ok(panel) => Outcome::job(locale, panel),
            Err(failure) => Outcome::failed(failure),
        },
        Delivery::Read => dispatch.read_root(&built.root()).await,
        Delivery::Batch => {
            let item = BatchItem::new(built.root(), built.validated().clone());
            dispatch
                .change(risk, params, Change::Batch(vec![item]))
                .await
        }
    };
    audit.record(&state, &user, outcome.audit()).await;
    let response = outcome.render(locale);
    if risk == Risk::Read {
        response
    } else {
        gate::close_dialog(response)
    }
}
