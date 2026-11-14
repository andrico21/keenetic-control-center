//! The maintenance actions of the storage page: Eject, Check and Format.
//!
//! Each is destructive: it needs `Destructive`, the kit asks for the router name and sends
//! the request again with the medium (and the filesystem) in its query string, and the
//! change runs through the change workflow. An unknown medium is refused first.

use askama::Template;
use axum::{
    Form,
    extract::{Path, RawQuery, State},
    response::Response,
};
use kcc_catalog::Risk;
use kcc_domain::{
    ChangeOp, Result as DomainResult, RouterCtx,
    storage::{self, MaintenanceAction, MaintenanceRequest},
};
use kcc_i18n::keys;

use super::shared::{NoDialog, merged, value};
use crate::{
    WebState,
    authz::CurrentUser,
    errors,
    page::{Localize as _, Shell},
    page_kit::{
        action::{Action, Operation},
        change::Change,
        confirm::Resubmit,
        context::fragment_shell,
        request::{Params, missing, with_query},
        respond::Answer,
        submit::{Planned, Submission},
    },
};

/// The filesystems Format offers.
const FILESYSTEMS: [&str; 3] = ["ext4", "ntfs", "fat32"];

/// Whether the router of `domain` has the medium `id`.
// cancel-safe: reads only.
async fn known(domain: &RouterCtx, id: &str) -> bool {
    storage::read_media(domain)
        .await
        .is_ok_and(|media| media.iter().any(|volume| volume.id.as_deref() == Some(id)))
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
    Submission::new(action, &Params::of(pairs), NoDialog)
        .confirming(Risk::Destructive, again)
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
/// Answers 404 for an unknown medium, and what the kit answers when the router or the
/// permission is missing.
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
    if !known(&domain, &media).await {
        action.abandon("not_found").await;
        return Err(missing());
    }
    let path = format!("/ui/r/{router}/system/storage/eject");
    let again = resubmit(&path, &[("media", &media)]);
    Ok(run(action, (pairs, again), |ctx| {
        storage::plan_eject(ctx, &router, user.role(), &media, true)
    })
    .await)
}

/// `POST /ui/r/{router}/system/storage/check?media=`: checks one medium's filesystem
/// once the router name was typed.
///
/// # Errors
///
/// Answers 404 for an unknown medium, and what the kit answers when the router or the
/// permission is missing.
pub(crate) async fn check(
    State(state): State<WebState>,
    Path(router): Path<String>,
    RawQuery(query): RawQuery,
    user: CurrentUser,
    Form(form): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let pairs = merged(query.as_deref(), form);
    let action = Operation::write(&storage::DESCRIPTOR, "partition_check", "web.storage_check")
        .open(&state, &user, &router)
        .await?;
    let domain = action.context().await?;
    let media = value(&pairs, "media").unwrap_or_default().to_owned();
    if !known(&domain, &media).await {
        action.abandon("not_found").await;
        return Err(missing());
    }
    let path = format!("/ui/r/{router}/system/storage/check");
    let again = resubmit(&path, &[("media", &media)]);
    Ok(run(action, (pairs, again), |ctx| {
        let request = MaintenanceRequest::new(&router, user.role(), &media, None, true);
        storage::plan_maintenance(ctx, MaintenanceAction::Check, request)
    })
    .await)
}

/// The format dialog: the filesystem to create on one medium.
#[derive(Template)]
#[template(path = "partials/system_format_dialog.html")]
struct FormatDialog {
    /// Locale carrier.
    shell: Shell,
    /// Where the form posts.
    post_to: String,
    /// The medium.
    media: String,
    /// The filesystems offered.
    filesystems: [&'static str; 3],
}

localized!(FormatDialog);

/// `GET /ui/r/{router}/system/storage/format?media=`: the format dialog.
///
/// # Errors
///
/// Answers 404 for an unknown medium, and what the kit answers when the router or the
/// permission is missing.
pub(crate) async fn format_dialog(
    State(state): State<WebState>,
    Path(router): Path<String>,
    user: CurrentUser,
    Form(query): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let action = Operation::write(
        &storage::DESCRIPTOR,
        "partition_format",
        "web.storage_format",
    )
    .open(&state, &user, &router)
    .await?;
    let domain = action.context().await?;
    let media = value(&query, "media").unwrap_or_default().to_owned();
    if !known(&domain, &media).await {
        return Err(missing());
    }
    Ok(errors::render(&FormatDialog {
        shell: fragment_shell(action.locale()),
        post_to: format!("/ui/r/{router}/system/storage/format"),
        media,
        filesystems: FILESYSTEMS,
    }))
}

/// `POST /ui/r/{router}/system/storage/format`: formats one medium with the chosen
/// filesystem once the router name was typed.
///
/// # Errors
///
/// Answers 404 for an unknown medium or filesystem, and what the kit answers when the
/// router or the permission is missing.
pub(crate) async fn format(
    State(state): State<WebState>,
    Path(router): Path<String>,
    RawQuery(query): RawQuery,
    user: CurrentUser,
    Form(form): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let pairs = merged(query.as_deref(), form);
    let action = Operation::write(
        &storage::DESCRIPTOR,
        "partition_format",
        "web.storage_format",
    )
    .open(&state, &user, &router)
    .await?;
    let domain = action.context().await?;
    let media = value(&pairs, "media").unwrap_or_default().to_owned();
    let filesystem = value(&pairs, "filesystem").unwrap_or_default().to_owned();
    if !FILESYSTEMS.contains(&filesystem.as_str()) || !known(&domain, &media).await {
        action.abandon("not_found").await;
        return Err(missing());
    }
    let path = format!("/ui/r/{router}/system/storage/format");
    let again = resubmit(&path, &[("media", &media), ("filesystem", &filesystem)]);
    Ok(run(action, (pairs, again), |ctx| {
        let request =
            MaintenanceRequest::new(&router, user.role(), &media, Some(&filesystem), true);
        storage::plan_maintenance(ctx, MaintenanceAction::Format, request)
    })
    .await)
}
