//! The WireGuard `.conf` import: a multipart upload of at most 64 KiB, parsed by the VPN
//! client domain's strict parser, checked for what the router can take, and imported
//! through the change workflow.
//!
//! The file's private key, preshared keys and obfuscation keys are parsed into secret
//! strings and sent only through the VPN client domain's protected requests, whose
//! read-back checks that the router reports each key, never its value; they are never
//! logged, audited or shown. Without a private key the router generates the key pair. An
//! error names a line and a WireGuard field, never a value taken from the file.

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
use kcc_domain::vpn_clients::{self, wireguard::WireGuardConfig};
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use secrecy::{SecretString, zeroize::Zeroizing};

use super::{
    screen::{Answered, read_back},
    vpn_conf,
    vpn_forms::VpnForm,
    vpn_pages::{Spot, region},
    vpn_read::exists,
};
use crate::{
    WebState,
    authz::CurrentUser,
    markup::Rendered,
    page_kit::{
        action::Operation,
        change::Change,
        confirm::Resubmit,
        form::FormDialog,
        outcome::{Failure, Outcome},
        request::{Params, shown_query},
        respond::Answer,
        submit::{self, Invalid, Planned, Submission},
    },
    secret_pages::reply::confirmed,
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
    let (mut shown, mut checked) = match read {
        Ok(found) => {
            let shown = dialog(&router, locale, &found.name);
            match vpn_conf::checked((&found.name, found.file.as_ref()), locale) {
                Ok(ready) => (shown, Ok(ready)),
                Err(problems) => {
                    let invalid = problems
                        .into_iter()
                        .fold(shown, |form, (field, text)| form.error(field, &text));
                    (invalid, Err(Invalid::from(Vec::new())))
                }
            }
        }
        Err(Unread::TooLarge) => {
            action.abandon("too_large").await;
            return Err(too_large(&router, locale).into());
        }
        Err(Unread::Unreadable) => {
            let text = tr(locale, keys::WEB_VPN_ERROR_FILE, None);
            let unread = dialog(&router, locale, "").error("file", &text);
            (unread, Err(Invalid::from(Vec::new())))
        }
    };
    let mut unread = None;
    if let Ok((name, _config)) = &checked {
        // A new connection never reuses a name: that would regenerate a live tunnel's key.
        match exists(&action.context().await?, name).await {
            Ok(false) => {}
            Ok(true) => {
                let text = tr(locale, keys::WEB_VPN_ERROR_NAME_TAKEN, None);
                shown = shown.error("name", &text);
                checked = Err(Invalid::from(Vec::new()));
            }
            Err(error) => unread = Some(error),
        }
    }
    let importing = Importing::new(
        shown,
        checked.as_ref().ok().map(|(_name, config)| config),
        locale,
    );
    let params = Params::default();
    let resubmit = Resubmit::new(format!("/ui/r/{router}/vpn/import"), "#page-outcome");
    Ok(Submission::new(action, &params, importing, resubmit)
        .submit(
            |_params| checked,
            async |(name, config), ctx| {
                if let Some(error) = unread {
                    return Err(error);
                }
                let operation = vpn_clients::plan_wireguard_import(ctx, &name, &config).await?;
                let request = vpn_clients::change_request(&operation)?;
                Ok(Planned::of(&[operation], Change::Cli(request)))
            },
            async |ctx| {
                let viewer = Spot::Connections
                    .viewer(ctx, &user, &router)
                    .with_table_query(shown_query(&headers));
                read_back(region(ctx, &Spot::Connections, &viewer).await)
            },
        )
        .await)
}

/// The import dialog as the form of the import.
///
/// Values that failed their check come back in the dialog, with their errors already on
/// it; a refused import under the file. A success with keys from the file says the
/// router reports them, and every answer to the import notes the file's fields it left
/// out. It holds no key: the file goes from the check to the plan only.
struct Importing {
    /// The dialog, with the errors of values that failed their check.
    dialog: FormDialog,
    /// The headline of a success that imported keys from the file.
    keyed: Option<String>,
    /// The file's fields the import leaves out.
    notes: Vec<String>,
}

impl Importing {
    /// `dialog`, importing `config` when it passed its check, in `locale`.
    fn new(dialog: FormDialog, config: Option<&WireGuardConfig>, locale: Locale) -> Self {
        Self {
            dialog,
            keyed: config
                .filter(|found| vpn_conf::keyed(found))
                .map(|_found| tr(locale, keys::WEB_SECRET_IMPORT_DONE, None)),
            notes: config.map_or_else(Vec::new, |found| vpn_conf::skipped(found, locale)),
        }
    }
}

impl submit::Form for Importing {
    fn answer_invalid(self, _invalid: Invalid, _locale: Locale) -> Response {
        self.dialog.invalid()
    }

    fn answer_refused(self, failure: Failure, _locale: Locale) -> Response {
        self.dialog.error("file", failure.message()).invalid()
    }

    fn answer_changed(
        self,
        outcome: Outcome,
        refreshed: Option<Rendered>,
        locale: Locale,
    ) -> Response {
        let shown = match self.keyed {
            Some(headline) => confirmed(outcome, headline),
            None => outcome,
        };
        Answered::new(shown, locale)
            .read_back(refreshed)
            .notes(self.notes)
            .respond()
    }
}

/// The import dialog on `router`, its name field holding `name`.
fn dialog(router: &str, locale: Locale, name: &str) -> FormDialog {
    VpnForm::Import
        .dialog(router, locale)
        .values(&Params::of(vec![("name".to_owned(), name.to_owned())]))
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
                let bytes = Zeroizing::new(Vec::from(
                    field.bytes().await.map_err(|error| unread(&error))?,
                ));
                if !bytes.is_empty() {
                    let text = str::from_utf8(&bytes).map_err(|_error| Unread::Unreadable)?;
                    found.file = Some(SecretString::from(text));
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
