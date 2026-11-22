//! The maintenance actions of the storage page: Eject, and Prepare for Entware (an ext4
//! initialize of the whole medium).
//!
//! Both are destructive: they need `Destructive`, the kit asks for the router name and
//! sends the request again with the medium in its query string, and the change runs
//! through the change workflow. An unknown medium is refused first. The drive Entware
//! runs from asks a second time (`storage_guard`).

use axum::{
    Form,
    extract::{Path, RawQuery, State},
    response::Response,
};
use kcc_app::permissions::Permission;
use kcc_catalog::Risk;
use kcc_domain::{ChangeOp, Result as DomainResult, RouterCtx, entware, storage};

use super::{
    shared::{merged, unread, value},
    storage_guard::{Act, EntwareGuard, acknowledged},
};
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

/// Ejecting a medium, audited as `web.storage_eject`.
const EJECT: Operation = Operation::write(&storage::DESCRIPTOR, "eject", "web.storage_eject");

/// Initializing a medium with ext4 for Entware, audited as `web.storage_initialize`.
pub(crate) const INITIALIZE: Operation = Operation::planned(
    "media initialize",
    (Permission::Destructive, Risk::Destructive),
    "web.storage_initialize",
);

/// Whether the router of `domain` has the medium `id`.
///
/// # Errors
///
/// Returns the read failure: a medium kcc could not see is not taken as absent.
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, reads only.
async fn known(domain: &RouterCtx, id: &str) -> DomainResult<bool> {
    let media = storage::read_media(domain).await?;
    Ok(media.iter().any(|volume| volume.id.as_deref() == Some(id)))
}

/// One storage action on one medium, planned with `plan` once the router name was typed.
///
/// The medium is checked against the router first; `plan` gets the Entware drive and
/// whether it was acknowledged, and the Entware drive asks a second time.
///
/// # Errors
///
/// Answers 404 for an unknown medium, and the failure when the media or the Entware drive
/// cannot be read.
// NOT cancel-safe: dropped after the change is sent, the router may keep it without its read-back,
// audit entry or timer cleanup.
async fn run<P>(
    action: Action<'_>,
    (pairs, act): (Vec<(String, String)>, Act),
    plan: P,
) -> Result<Response, Answer>
where
    P: FnOnce(&RouterCtx, &str, (Option<&str>, bool)) -> DomainResult<ChangeOp>,
{
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
    let entware_media = match entware::configured_media(&domain).await {
        Ok(found) => found,
        Err(error) => {
            tracing::warn!(%error, "the Entware drive could not be read");
            return Err(unread(action).await);
        }
    };
    let slug = match act {
        Act::Eject => "eject",
        Act::Initialize => "initialize",
    };
    let path = format!("/ui/r/{}/system/storage/{slug}", action.router());
    let again = Resubmit::new(with_query(&path, &[("media", &media)]), "#page-outcome");
    let ok = acknowledged(&pairs);
    let guard = EntwareGuard::new(path, media.clone(), act);
    let answer = Submission::new(action, &Params::of(pairs), guard, again)
        .confirming(Risk::Destructive)
        .submit(
            |_params| Ok(()),
            async |(), ctx| {
                let operation = plan(ctx, &media, (entware_media.as_deref(), ok))?;
                let request = storage::change_request(&operation)?;
                Ok(Planned::of(&[operation], Change::Cli(request)))
            },
            async |_ctx| None,
        )
        .await;
    Ok(answer)
}

/// `POST /ui/r/{router}/system/storage/eject?media=`: ejects one medium once the router
/// name was typed, and for the Entware drive once that was acknowledged too.
///
/// # Errors
///
/// Answers 404 for an unknown medium, the failure when the media cannot be read, and what
/// the kit answers when the router or the permission is missing.
// NOT cancel-safe: dropped after the change is sent, the router may keep it without its read-back,
// audit entry or timer cleanup.
pub(crate) async fn eject(
    State(state): State<WebState>,
    Path(router): Path<String>,
    RawQuery(query): RawQuery,
    user: CurrentUser,
    Form(form): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let pairs = merged(query.as_deref(), form);
    let action = EJECT.open(&state, &user, &router).await?;
    run(
        action,
        (pairs, Act::Eject),
        |ctx, media, (entware_media, ok)| {
            storage::plan_eject(ctx, &router, user.role(), media, true, entware_media, ok)
        },
    )
    .await
}

/// `POST /ui/r/{router}/system/storage/initialize?media=`: prepares one medium for
/// Entware.
///
/// The router wipes the medium and creates swap and an ext4 partition once the router
/// name was typed, and for the Entware drive once that was acknowledged too. It
/// initializes in the background; the page says it started.
///
/// # Errors
///
/// Answers 404 for an unknown medium, the failure when the media cannot be read, and what
/// the kit answers when the router or the permission is missing.
// NOT cancel-safe: dropped after the change is sent, the router may keep it without its audit
// entry.
pub(crate) async fn initialize(
    State(state): State<WebState>,
    Path(router): Path<String>,
    RawQuery(query): RawQuery,
    user: CurrentUser,
    Form(form): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let pairs = merged(query.as_deref(), form);
    let action = INITIALIZE.open(&state, &user, &router).await?;
    run(
        action,
        (pairs, Act::Initialize),
        |ctx, media, (entware_media, ok)| {
            storage::plan_initialize(ctx, &router, user.role(), media, true, entware_media, ok)
        },
    )
    .await
}
