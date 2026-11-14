//! Deleting a segment kcc created.
//!
//! The dialog lists what the delete removes and which ports stay, and asks for the
//! router's name. The delete runs only when the name matches and the segment is still the
//! one the dialog showed: the dialog carries a fingerprint of its summary, compared with a
//! fresh read; the segments domain then checks the router again inside the change set.

use axum::{
    Form,
    extract::{Path, Query, State},
    response::Response,
};
use fluent_bundle::FluentArgs;
use kcc_domain::{
    RouterCtx,
    segments::{self, SegmentView},
};
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

use super::{answer, segment_list::Region, segments::step_failure};
use crate::{
    WebState,
    authz::CurrentUser,
    errors,
    page_kit::{
        action::Operation,
        change::Applied,
        context::fragment_shell,
        failure::plan_failure,
        family::Family,
        outcome::{Failure, Outcome},
        request::missing,
        respond::{self, Answer},
        typed_name::{TypedNameDialog, TypedNameForm},
    },
};

/// Deleting a segment, audited as `web.segments_delete`.
const DELETE: Operation = Operation::write(&segments::DESCRIPTOR, "delete", "web.segments_delete");

/// Which segment a delete is about.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Which {
    /// Segment number.
    id: u16,
    /// The fingerprint of the summary the confirming dialog showed.
    #[serde(default)]
    seen: Option<String>,
}

/// `GET /ui/r/{router}/segments/delete?id=`: the confirmation listing what goes.
///
/// # Errors
///
/// Answers 404 for a segment the router does not have, and what the kit answers when the
/// router or the permission is missing.
// cancel-safe: reads only.
pub(crate) async fn dialog(
    State(state): State<WebState>,
    Path(router): Path<String>,
    user: CurrentUser,
    Query(which): Query<Which>,
) -> Result<Response, Answer> {
    let action = DELETE.open(&state, &user, &router).await?;
    let locale = action.locale();
    let domain = action.context().await?;
    let view = find(&domain, which.id, locale).await?.ok_or_else(missing)?;
    let dialog = confirmation(&router, &view, locale);
    Ok(respond::in_dialog(errors::render(&dialog)))
}

/// `POST /ui/r/{router}/segments/delete?id=&seen=`: deletes the segment.
///
/// The router's name must be typed and the segment must still be the one the dialog
/// showed; the outcome and the list read back land in the page.
///
/// # Errors
///
/// Answers the dialog with its error (422) for a wrong name or a segment that changed, and
/// what the kit answers when the router or the permission is missing.
// NOT cancel-safe: the delete runs step by step through the change workflow.
pub(crate) async fn delete(
    State(state): State<WebState>,
    Path(router): Path<String>,
    user: CurrentUser,
    Query(which): Query<Which>,
    Form(form): Form<TypedNameForm>,
) -> Result<Response, Answer> {
    let action = DELETE.open(&state, &user, &router).await?;
    let locale = action.locale();
    let domain = action.context().await?;
    let Some(view) = find(&domain, which.id, locale).await? else {
        action.abandon("not_found").await;
        let gone = Failure::new(
            tr(locale, keys::WEB_SEGMENTS_DELETE_GONE, None),
            "not_found",
        );
        let listed = Region::read_back(&domain, &router, locale).await;
        let answered = answer(Outcome::failed(gone), listed, None, locale);
        return Ok(respond::retarget(answered, "#page-outcome"));
    };
    if !(form.confirmed() && form.name() == router) {
        action.abandon("confirmation_mismatch").await;
        let dialog = confirmation(&router, &view, locale);
        return Err(refuse(
            dialog,
            tr(locale, keys::WEB_ADMIN_ERROR_CONFIRM, None),
        ));
    }
    if which.seen.as_deref() != Some(fingerprint(&view).as_str()) {
        action.abandon("conflict").await;
        let dialog = confirmation(&router, &view, locale);
        return Err(refuse(
            dialog,
            tr(locale, keys::WEB_SEGMENTS_DELETE_CHANGED, None),
        ));
    }
    let risk = match view.deletion_plan(&domain).await {
        Ok(operation) => operation.risk,
        Err(error) => {
            let failure = plan_failure(Family::Changes, locale, &error);
            let shown = Outcome::failed(failure).render(locale);
            return Err(Answer::from(respond::retarget(shown, "#page-outcome")));
        }
    };
    let mut note = None;
    let outcome = action
        .run_with(
            risk,
            async |changes, context| match segments::delete_discovered(changes, context, &view)
                .await
            {
                Ok(_summary) => changes
                    .current_last_change()
                    .await
                    .map(|last| Applied::Done {
                        unsaved: last.unsaved,
                    }),
                Err(error) => {
                    let (said, source) = step_failure(error, locale);
                    note = said;
                    Err(source)
                }
            },
        )
        .await;
    let listed = Region::read_back(&domain, &router, locale).await;
    Ok(respond::retarget(
        answer(outcome, listed, note, locale),
        "#page-outcome",
    ))
}

/// The segment `id` of `domain`'s router, if it has one.
///
/// # Errors
///
/// Answers the read's failure, shown in the page's outcome region.
// cancel-safe: reads only.
async fn find(domain: &RouterCtx, id: u16, locale: Locale) -> Result<Option<SegmentView>, Answer> {
    match segments::read_segments(domain).await {
        Ok(views) => Ok(views.into_iter().find(|view| view.id == id)),
        Err(error) => {
            let failure = plan_failure(Family::Changes, locale, &error);
            let shown = Outcome::failed(failure).render(locale);
            Err(Answer::from(respond::retarget(shown, "#page-outcome")))
        }
    }
}

/// The confirmation deleting `view` from `router`: what goes, which ports stay, and the
/// router's name to type.
fn confirmation(router: &str, view: &SegmentView, locale: Locale) -> TypedNameDialog {
    let summary = view.delete_summary();
    let lead = |key: MessageKey, value: u16| {
        let mut args = FluentArgs::new();
        args.set("value", value.to_string());
        tr(locale, key, Some(&args))
    };
    let action = format!(
        "/ui/r/{router}/segments/delete?id={}&seen={}",
        view.id,
        fingerprint(view)
    );
    TypedNameDialog::new(
        fragment_shell(locale),
        action,
        router,
        (
            keys::WEB_SEGMENTS_DELETE_TITLE,
            keys::WEB_SEGMENTS_DELETE_TEXT,
        ),
    )
    .with_button(keys::WEB_SEGMENTS_DELETE_CONFIRM)
    .with_list(
        lead(keys::WEB_SEGMENTS_DELETE_REMOVED, summary.id),
        summary.owned_contexts,
    )
    .with_list(
        lead(keys::WEB_SEGMENTS_DELETE_KEPT, view.vlan_id.value()),
        summary.preserved_ports,
    )
}

/// `dialog` again with `error`, as 422 in the dialog.
fn refuse(mut dialog: TypedNameDialog, error: String) -> Answer {
    dialog.set_error(error);
    respond::in_dialog(respond::unprocessable(&dialog)).into()
}

/// A short fingerprint of what deleting `view` removes and keeps.
fn fingerprint(view: &SegmentView) -> String {
    let summary = view.delete_summary();
    let mut digest = Sha256::new();
    digest.update(view.vlan_id.value().to_be_bytes());
    for (part, names) in [
        (0_u8, &summary.owned_contexts),
        (1, &summary.preserved_ports),
    ] {
        digest.update([part]);
        for name in names {
            digest.update(name.as_bytes());
            digest.update([0_u8]);
        }
    }
    digest
        .finalize()
        .iter()
        .take(8)
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .concat()
}
