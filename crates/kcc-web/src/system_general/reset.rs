//! The factory reset of the general page.
//!
//! The router name is typed into the kit's confirmation, then the system domain's terminal
//! reset runs through the change workflow. Afterwards the router's state is unknown, so
//! the page shows no unsaved badge and reads nothing back.

use axum::{
    Form,
    extract::{Path, State},
    response::Response,
};
use kcc_app::workflow::WorkflowError;
use kcc_domain::system;

use crate::{
    WebState,
    authz::CurrentUser,
    page_kit::{
        action::Operation,
        change::Applied,
        confirm::Resubmit,
        request::Params,
        respond::Answer,
        submit::{Formless, Planned, Submission},
    },
};

/// The factory reset, audited as `web.system_factory_reset`.
const RESET: Operation = Operation::write(
    &system::DESCRIPTOR,
    "factory_reset",
    "web.system_factory_reset",
);

/// `POST /ui/r/{router}/system/general/reset`: asks for the router name, then resets the
/// router to its factory settings.
///
/// # Errors
///
/// Answers what the kit answers when the router or the permission is missing.
pub(crate) async fn reset(
    State(state): State<WebState>,
    Path(router): Path<String>,
    user: CurrentUser,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let action = RESET.open(&state, &user, &router).await?;
    let resubmit = Resubmit::new(
        format!("/ui/r/{router}/system/general/reset"),
        "#page-outcome",
    );
    let params = Params::of(pairs);
    let typed = params.confirmation().name().unwrap_or_default().to_owned();
    let named = router.clone();
    Ok(Submission::new(action, &params, Formless, resubmit)
        .submit(
            |_params| Ok(()),
            async |(), _ctx| {
                Ok(Planned::described(move |changes, context| {
                    Box::pin(async move {
                        system::factory_reset(changes, context, &named, &typed)
                            .await
                            .map(|result| Applied::Terminal(result.responses))
                            .map_err(WorkflowError::from)
                    })
                }))
            },
            async |_ctx| None,
        )
        .await)
}
