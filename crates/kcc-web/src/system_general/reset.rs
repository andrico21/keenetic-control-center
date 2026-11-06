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
use kcc_catalog::Risk;
use kcc_domain::{
    DomainError,
    system::{self, FactoryResetError},
};

use crate::{
    WebState,
    authz::CurrentUser,
    page_kit::{
        action::Operation,
        change::Applied,
        confirm::{Confirmation, Resubmit},
        respond::Answer,
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
    let confirmation = Confirmation::from_pairs(&pairs);
    if let Some(prompt) = action.confirm(Risk::Destructive, &confirmation, resubmit) {
        return Ok(prompt);
    }
    let locale = action.locale();
    let typed = confirmation.name().unwrap_or_default().to_owned();
    let outcome = action
        .run_with(Risk::Destructive, async |changes, domain| {
            system::factory_reset(changes, domain, &router, &typed)
                .await
                .map(|result| Applied::Terminal(result.responses))
                .map_err(workflow_error)
        })
        .await;
    Ok(super::answer(outcome, None, locale))
}

/// The change-workflow error of a refused reset; the typed name was already checked, so a
/// mismatch here is an internal fault.
fn workflow_error(error: FactoryResetError) -> WorkflowError {
    match error {
        FactoryResetError::Workflow(inner) => inner,
        FactoryResetError::Domain(DomainError::Validation { issues }) => {
            WorkflowError::CatalogValidation { issues }
        }
        FactoryResetError::ConfirmationMismatch | FactoryResetError::Domain(_) | _ => {
            WorkflowError::InvalidResponse
        }
    }
}
