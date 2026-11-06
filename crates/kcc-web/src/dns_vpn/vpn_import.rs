//! The WireGuard `.conf` import: a multipart upload of at most 64 KiB, parsed by the VPN
//! client domain's strict parser, checked for what the router can take, and imported
//! through the change workflow.
//!
//! The file's private and preshared keys are parsed into secret strings and never sent,
//! logged, audited or shown: the router generates the connection's own key pair. An error
//! names a line and a WireGuard field, never a value taken from the file.

use core::str;

use axum::{
    extract::{
        Multipart, Path, Request, State,
        multipart::{MultipartError, MultipartRejection},
    },
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
};
use kcc_domain::vpn_clients;
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use secrecy::SecretString;

use super::{
    flow,
    form::{FormDialog, Values},
    vpn_conf,
    vpn_forms::VpnForm,
    vpn_pages::{Spot, region},
    vpn_read::exists,
};
use crate::{
    WebState,
    authz::CurrentUser,
    page_kit::{action::Operation, failure::plan_failure, family::Family, respond::Answer},
};

/// Largest import request, file and fields together: 64 KiB.
pub(crate) const UPLOAD_LIMIT: usize = 64 * 1024;

/// The import, audited as `web.vpn_import`.
const IMPORT: Operation = VpnForm::Import.operation();

/// The uploaded fields: the connection's name and the file, kept secret.
struct Upload {
    /// The connection's name as typed.
    name: String,
    /// The file's text; `None` when no file was chosen.
    file: Option<SecretString>,
}

/// Why an upload could not be read.
enum Unread {
    /// The body is larger than [`UPLOAD_LIMIT`].
    TooLarge,
    /// The body is not a readable form, or the file is not text.
    Unreadable,
}

/// `POST /ui/r/{router}/vpn/import`: imports a WireGuard `.conf` file as a new connection.
///
/// # Errors
///
/// Answers the dialog with field errors (422), or with the size error (413), and what the
/// kit answers when the router or the permission is missing.
pub(crate) async fn import(
    State(state): State<WebState>,
    Path(router): Path<String>,
    headers: HeaderMap,
    user: CurrentUser,
    multipart: Result<Multipart, MultipartRejection>,
) -> Result<Response, Answer> {
    let action = IMPORT.open(&state, &user, &router).await?;
    let locale = action.locale();
    let read = match multipart {
        Ok(fields) => upload(fields).await,
        Err(_rejection) => Err(Unread::Unreadable),
    };
    let found = match read {
        Ok(found) => found,
        Err(Unread::TooLarge) => {
            action.abandon("too_large").await;
            return Err(too_large(&router, locale).into());
        }
        Err(Unread::Unreadable) => {
            action.abandon("validation_failed").await;
            let text = tr(locale, keys::WEB_VPN_ERROR_FILE, None);
            return Err(dialog(&router, locale, "")
                .error("file", &text)
                .invalid()
                .into());
        }
    };
    let shown = dialog(&router, locale, &found.name);
    let (name, config) = match vpn_conf::checked((&found.name, found.file.as_ref()), locale) {
        Ok(ready) => ready,
        Err(problems) => {
            action.abandon("validation_failed").await;
            let invalid = problems
                .into_iter()
                .fold(shown, |form, (field, text)| form.error(field, &text));
            return Err(invalid.invalid().into());
        }
    };
    let ctx = action.context().await?;
    // A new connection never reuses a name: that would regenerate a live tunnel's key.
    let planned = exists(&ctx, &name).await.and_then(|used| {
        let operation = vpn_clients::plan_wireguard_import(&ctx, &name, &config)?;
        Ok((used, vpn_clients::change_request(&operation)?))
    });
    let request = match planned {
        Ok((false, request)) => request,
        Ok((true, _)) => {
            action.abandon("validation_failed").await;
            let text = tr(locale, keys::WEB_VPN_ERROR_NAME_TAKEN, None);
            return Err(shown.error("name", &text).invalid().into());
        }
        Err(error) => {
            let failure = plan_failure(Family::Changes, locale, &error);
            action.abandon("validation_failed").await;
            return Err(shown.error("file", failure.message()).invalid().into());
        }
    };
    let viewer = Spot::Connections
        .viewer(&ctx, &user, &router)
        .with_query(flow::shown_query(&headers));
    let answered = flow::apply(action, request, async || {
        region(&ctx, &Spot::Connections, &viewer).await
    })
    .await;
    Ok(answered.notes(vpn_conf::skipped(&config, locale)).respond())
}

/// The import dialog on `router`, its name field holding `name`.
fn dialog(router: &str, locale: Locale, name: &str) -> FormDialog {
    VpnForm::Import
        .dialog(router, locale)
        .values(&Values::new(vec![("name".to_owned(), name.to_owned())]))
}

/// The import dialog with the size error, as 413.
fn too_large(router: &str, locale: Locale) -> Response {
    let text = tr(locale, keys::WEB_VPN_ERROR_TOO_LARGE, None);
    let mut response = dialog(router, locale, "").error("file", &text).invalid();
    *response.status_mut() = StatusCode::PAYLOAD_TOO_LARGE;
    response
}

/// Answers a request the body limit stopped (413 with no dialog) with the import dialog
/// and its localized size error.
pub(crate) async fn limit(request: Request, next: Next) -> Response {
    let locale = request
        .extensions()
        .get::<CurrentUser>()
        .map(CurrentUser::locale);
    let router = request
        .uri()
        .path()
        .strip_prefix("/ui/r/")
        .and_then(|rest| rest.split('/').next())
        .map(str::to_owned);
    let response = next.run(request).await;
    let bare = response.status() == StatusCode::PAYLOAD_TOO_LARGE
        && !response.headers().contains_key("hx-retarget");
    match (bare, locale, router) {
        (true, Some(found), Some(id)) => too_large(&id, found),
        (_, _, _) => response,
    }
}

/// The name and the file of `fields`; other fields are ignored.
///
/// # Errors
///
/// Returns why the upload could not be read.
// cancel-safe: reads the request body only.
async fn upload(mut fields: Multipart) -> Result<Upload, Unread> {
    let mut found = Upload {
        name: String::new(),
        file: None,
    };
    while let Some(field) = fields.next_field().await.map_err(|error| unread(&error))? {
        match field.name() {
            Some("name") => found.name = field.text().await.map_err(|error| unread(&error))?,
            Some("file") => {
                let bytes = field.bytes().await.map_err(|error| unread(&error))?;
                if !bytes.is_empty() {
                    let text = str::from_utf8(&bytes).map_err(|_error| Unread::Unreadable)?;
                    found.file = Some(SecretString::from(text.to_owned()));
                }
            }
            Some(_) | None => {}
        }
    }
    Ok(found)
}

/// Why reading a multipart field failed.
fn unread(error: &MultipartError) -> Unread {
    if error.status() == StatusCode::PAYLOAD_TOO_LARGE {
        Unread::TooLarge
    } else {
        Unread::Unreadable
    }
}
