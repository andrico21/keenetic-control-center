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

use super::shared::{merged, value};
use crate::{
    WebState,
    authz::CurrentUser,
    errors,
    page::{Localize as _, Shell},
    page_kit::{
        action::{Action, Operation},
        change::Change,
        confirm::{Confirmation, Resubmit},
        context::fragment_shell,
        failure::plan_failure,
        family::Family,
        outcome::Outcome,
        request::{missing, with_query},
        respond::{Answer, changed},
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

/// Runs the confirmed `planned` change of `action` and answers with its outcome; a plan
/// the catalog refuses is shown as such and sends nothing.
// NOT cancel-safe: see `Action::run`.
async fn run(action: Action<'_>, planned: DomainResult<ChangeOp>) -> Response {
    let locale = action.locale();
    match planned.and_then(|operation| storage::change_request(&operation)) {
        Ok(request) => {
            let outcome = action.run(Risk::Destructive, Change::Cli(request)).await;
            changed(outcome, None, None, locale)
        }
        Err(error) => {
            action.abandon("validation_failed").await;
            let failure = plan_failure(Family::Changes, locale, &error);
            let outcome =
                Outcome::invalid(Family::Changes, locale, vec![failure.message().to_owned()]);
            changed(outcome, None, None, locale)
        }
    }
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
    if let Some(prompt) =
        action.confirm(Risk::Destructive, &Confirmation::from_pairs(&pairs), again)
    {
        return Ok(prompt);
    }
    let planned = storage::plan_eject(&domain, &router, user.role(), &media, true);
    Ok(run(action, planned).await)
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
    if let Some(prompt) =
        action.confirm(Risk::Destructive, &Confirmation::from_pairs(&pairs), again)
    {
        return Ok(prompt);
    }
    let request = MaintenanceRequest::new(&router, user.role(), &media, None, true);
    let planned = storage::plan_maintenance(&domain, MaintenanceAction::Check, request);
    Ok(run(action, planned).await)
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
    let confirmation = Confirmation::from_pairs(&pairs);
    if let Some(prompt) = action.confirm(Risk::Destructive, &confirmation, again) {
        return Ok(prompt);
    }
    let request = MaintenanceRequest::new(&router, user.role(), &media, Some(&filesystem), true);
    let planned = storage::plan_maintenance(&domain, MaintenanceAction::Format, request);
    Ok(run(action, planned).await)
}
