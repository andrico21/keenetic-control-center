//! The maintenance action of the storage page: Eject.
//!
//! It is destructive: it needs `Destructive`, the kit asks for the router name and sends
//! the request again with the medium in its query string, and the change runs through the
//! change workflow. An unknown medium is refused first.

use axum::{
    Form,
    extract::{Path, RawQuery, State},
    response::Response,
};
use kcc_catalog::Risk;
use kcc_domain::{ChangeOp, Result as DomainResult, RouterCtx, storage};

use super::shared::{NoDialog, merged, unread, value};
use crate::{
    WebState,
    authz::CurrentUser,
    page_kit::{
        action::{Action, Operation},
        change::Change,
        confirm::Resubmit,
        request::{Params, missing, with_query},
        respond::Answer,
        submit::{Planned, Submission},
    },
};

/// Whether the router of `domain` has the medium `id`.
///
/// # Errors
///
/// Returns the read failure: a medium kcc could not see is not taken as absent.
// cancel-safe: reads only.
async fn known(domain: &RouterCtx, id: &str) -> DomainResult<bool> {
    let media = storage::read_media(domain).await?;
    Ok(media.iter().any(|volume| volume.id.as_deref() == Some(id)))
}

/// The kit's typed-name confirmation of a storage action, which sends the request to
/// `path` again with the `kept` pairs.
fn resubmit(path: &str, kept: &[(&str, &str)]) -> Resubmit {
    Resubmit::new(with_query(path, kept), "#page-outcome")
}

/// Plans the change with `plan` and runs it as `action` once the router name was typed.
///
/// Typing the name sends the request again by `again`; a plan the catalog refuses is
/// shown as such and sends nothing.
// NOT cancel-safe: see `Submission::submit`.
async fn run<P>(
    action: Action<'_>,
    (pairs, again): (Vec<(String, String)>, Resubmit),
    plan: P,
) -> Response
where
    P: FnOnce(&RouterCtx) -> DomainResult<ChangeOp>,
{
    Submission::new(action, &Params::of(pairs), NoDialog, again)
        .confirming(Risk::Destructive)
        .submit(
            |_params| Ok(()),
            async |(), ctx| {
                let operation = plan(ctx)?;
                let request = storage::change_request(&operation)?;
                Ok(Planned::of(&[operation], Change::Cli(request)))
            },
            async |_ctx| None,
        )
        .await
}

/// `POST /ui/r/{router}/system/storage/eject?media=`: ejects one medium once the router
/// name was typed.
///
/// # Errors
///
/// Answers 404 for an unknown medium, the failure when the media cannot be read, and what
/// the kit answers when the router or the permission is missing.
pub(crate) async fn eject(
    State(state): State<WebState>,
    Path(router): Path<String>,
    RawQuery(query): RawQuery,
    user: CurrentUser,
    Form(form): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let pairs = merged(query.as_deref(), form);
    let action = Operation::write(&storage::DESCRIPTOR, "eject", "web.storage_eject")
        .open(&state, &user, &router)
        .await?;
    let domain = action.context().await?;
    let media = value(&pairs, "media").unwrap_or_default().to_owned();
    match known(&domain, &media).await {
        Ok(true) => {}
        Ok(false) => {
            action.abandon("not_found").await;
            return Err(missing());
        }
        Err(error) => {
            tracing::warn!(%error, "router media could not be read");
            return Err(unread(action).await);
        }
    }
    let path = format!("/ui/r/{router}/system/storage/eject");
    let again = resubmit(&path, &[("media", &media)]);
    Ok(run(action, (pairs, again), |ctx| {
        storage::plan_eject(ctx, &router, user.role(), &media, true)
    })
    .await)
}
