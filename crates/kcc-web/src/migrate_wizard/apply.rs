//! A migration's apply, for the engine's `crate::wizard::apply`.
//!
//! Its words, the permissions it needs, the engine's request built again from a fresh
//! read with the report and plan kept, and the preview with a reason.

use kcc_app::permissions::Permission;
use kcc_i18n::{bundle::MessageKey, keys};

use super::{
    access::Visit,
    apply_request::{Prepared, Refused},
    preview::{Panel, apply_permissions},
    record::Record,
};
use crate::{
    WebState, errors,
    page_kit::{context::fragment_shell, respond::Answer},
    wizard::{
        applying::{Applying, Failure, Starting},
        flow::Flow as _,
        screen,
        store::Kept,
    },
};

impl Applying for Record {
    const APPLY_AUDIT: &'static str = "web.migrate_apply";
    const APPLY_END_AUDIT: &'static str = "web.migrate_apply_end";
    const CONFIRM: (MessageKey, MessageKey, MessageKey) = (
        keys::WEB_MIGRATE_APPLY_CONFIRM_TITLE,
        keys::WEB_MIGRATE_APPLY_CONFIRM_TEXT,
        keys::WEB_MIGRATE_APPLY,
    );
    const BUSY: MessageKey = keys::WEB_MIGRATE_APPLY_BUSY;

    fn apply_permissions(&self) -> Vec<Permission> {
        apply_permissions(self)
    }

    fn prepare(
        visit: &mut Visit<'_>,
        state: &WebState,
    ) -> impl Future<Output = Result<Starting, Failure>> + Send {
        prepare(visit, state)
    }

    fn refusal(
        visit: &Visit<'_>,
        _state: &WebState,
        reason: String,
    ) -> impl Future<Output = Answer> + Send {
        refusal(visit, reason)
    }
}

/// The apply of `visit`, with its report and plan kept for the run's downloads.
///
/// # Errors
///
/// Returns why it cannot start: the preview's plan changed (the preview moves on to the
/// new one), the routers cannot be read, the plan cannot be built, or the run's files
/// cannot be read or written.
// NOT cancel-safe: dropped, a kept file or the record may still be written.
async fn prepare(visit: &mut Visit<'_>, state: &WebState) -> Result<Starting, Failure> {
    let prepared = match Prepared::new(visit, state).await {
        Ok(found) => found,
        Err(Refused::Changed(plan)) => {
            visit.record_mut().preview_ready(plan);
            visit.save().await.map_err(Failure::Broken)?;
            return Err(Failure::Refused(keys::WEB_MIGRATE_APPLY_CHANGED, "changed"));
        }
        Err(Refused::Unreadable) => {
            return Err(Failure::Refused(
                keys::WEB_MIGRATE_PROBLEM_UNREACHABLE,
                "unreachable",
            ));
        }
        Err(Refused::Broken) => {
            return Err(Failure::Refused(keys::WEB_MIGRATE_PROBLEM_PLAN, "refused"));
        }
        Err(Refused::Store(error)) => return Err(Failure::Broken(error)),
    };
    let id = visit.record().id().to_owned();
    let (request, texts, report, plan) = prepared.into_parts();
    let store = visit.services().store();
    store
        .keep(&id, Kept::Report, &report)
        .await
        .map_err(Failure::Broken)?;
    store
        .keep(&id, Kept::Plan, &plan)
        .await
        .map_err(Failure::Broken)?;
    Ok(Starting::new(request, texts))
}

/// The preview again with `reason`, as 422 in the step.
// cancel-safe: reads only.
async fn refusal(visit: &Visit<'_>, reason: String) -> Answer {
    match Panel::new(visit).await {
        Ok(panel) => screen::refused(&panel.refusing(reason)).into(),
        Err(error) => {
            let shell = fragment_shell(visit.services().user().locale());
            errors::internal(&error, shell).into()
        }
    }
}
