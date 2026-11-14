//! Reading step 1's form.
//!
//! The multipart fields, the 1 MiB size limit, and the source each kind reads (the
//! uploaded file, a stored backup, a router's startup configuration), checked to parse as
//! a router configuration.

use askama::Template;
use axum::{
    extract::{Multipart, Request, multipart::MultipartError},
    http::{HeaderValue, StatusCode},
    middleware::Next,
    response::Response,
};
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};
use kcc_rci::ConfigKind;
use secrecy::{ExposeSecret as _, SecretString};

use super::{kinds::Source, source::Field};
use crate::{
    authz::CurrentUser,
    errors,
    page::Shell,
    page_kit::context::fragment_shell,
    wizard::{analysis::parse_source, services::Services},
};

/// What the form sent.
#[derive(Default)]
pub(crate) struct Submitted {
    /// `router`, `file` or `backup`.
    kind: String,
    /// The router select.
    router: String,
    /// The backup select, `<router>/<name>`.
    backup: String,
    /// The file's name and text, when one was chosen.
    file: Option<(String, Vec<u8>)>,
}

/// A source the form chose and read.
pub(crate) struct Chosen {
    /// Where it came from.
    source: Source,
    /// Its text.
    text: SecretString,
}

/// Answers a body over the route's limit with the size error beside the file input.
pub(crate) async fn limit(request: Request, next: Next) -> Response {
    let locale = request
        .extensions()
        .get::<CurrentUser>()
        .map(CurrentUser::locale);
    let response = next.run(request).await;
    match (response.status() == StatusCode::PAYLOAD_TOO_LARGE, locale) {
        (true, Some(found)) => too_large(found),
        (_, _) => response,
    }
}

/// The size error, swapped into the feedback slot of the file input.
fn too_large(locale: Locale) -> Response {
    let mut response = errors::render(&Feedback {
        shell: fragment_shell(locale),
        message: tr(locale, keys::WEB_MIGRATE_SOURCE_ERROR_LARGE, None),
    });
    *response.status_mut() = StatusCode::PAYLOAD_TOO_LARGE;
    let headers = response.headers_mut();
    drop(headers.insert(
        "hx-retarget",
        HeaderValue::from_static("#source-file-feedback"),
    ));
    drop(headers.insert("hx-reswap", HeaderValue::from_static("innerHTML")));
    response
}

/// The size error beside the file input.
#[derive(Template)]
#[template(
    ext = "html",
    source = "<p class=\"field__error\" id=\"source-file-error\">{{ message }}</p>"
)]
struct Feedback {
    /// Locale carrier.
    shell: Shell,
    /// The message.
    message: String,
}

localized!(Feedback);

/// The fields of the form.
///
/// # Errors
///
/// Returns the message of an unreadable or too large body.
// cancel-safe: reads the request body only.
pub(crate) async fn read(mut fields: Multipart) -> Result<Submitted, MessageKey> {
    let mut found = Submitted::default();
    while let Some(field) = fields.next_field().await.map_err(|error| unread(&error))? {
        let name = field.name().map(str::to_owned);
        match name.as_deref() {
            Some("kind") => found.kind = field.text().await.map_err(|error| unread(&error))?,
            Some("router") => found.router = field.text().await.map_err(|error| unread(&error))?,
            Some("backup") => found.backup = field.text().await.map_err(|error| unread(&error))?,
            Some("file") => {
                let file_name = field.file_name().map(display_name).unwrap_or_default();
                let bytes = field.bytes().await.map_err(|error| unread(&error))?;
                if !bytes.is_empty() {
                    found.file = Some((file_name, bytes.to_vec()));
                }
            }
            Some(_) | None => {}
        }
    }
    Ok(found)
}

/// The message of a multipart failure.
fn unread(error: &MultipartError) -> MessageKey {
    if error.status() == StatusCode::PAYLOAD_TOO_LARGE {
        keys::WEB_MIGRATE_SOURCE_ERROR_LARGE
    } else {
        keys::WEB_MIGRATE_SOURCE_ERROR_FILE
    }
}

/// A file name the browser sent, cut to safe characters for display.
fn display_name(name: &str) -> String {
    let kept = name
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or_default()
        .chars()
        .filter(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_')
        })
        .take(64)
        .collect::<String>();
    if kept.is_empty() {
        "startup-config.txt".to_owned()
    } else {
        kept
    }
}

/// The uploaded file as the source.
///
/// # Errors
///
/// Returns the file field and its message when no file came or it is no configuration.
fn from_file(file: Option<(String, Vec<u8>)>) -> Result<Chosen, (Field, MessageKey)> {
    let (name, bytes) = file.ok_or((Field::File, keys::WEB_MIGRATE_SOURCE_ERROR_FILE))?;
    let text = String::from_utf8(bytes)
        .map(SecretString::from)
        .map_err(|_error| (Field::File, keys::WEB_MIGRATE_SOURCE_ERROR_PARSE))?;
    parse_source(&text)
        .map(drop)
        .map_err(|_problem| (Field::File, keys::WEB_MIGRATE_SOURCE_ERROR_PARSE))?;
    Ok(Chosen {
        source: Source::File { name },
        text,
    })
}

/// The stored backup `value` (`<router>/<name>`) as the source.
///
/// # Errors
///
/// Returns the backup field and its message for a backup the user may not use or that
/// does not parse.
// cancel-safe: reads only.
async fn from_backup(services: Services<'_>, value: &str) -> Result<Chosen, (Field, MessageKey)> {
    let refused = (Field::Backup, keys::WEB_MIGRATE_SOURCE_ERROR_BACKUP);
    let (router, name) = value.split_once('/').ok_or(refused)?;
    if !services.permits(router).await {
        return Err(refused);
    }
    let text = services
        .fleet()
        .workflow()
        .backups()
        .get(router, name)
        .map_err(|_error| refused)?;
    parse_source(&text)
        .map(drop)
        .map_err(|_problem| (Field::Backup, keys::WEB_MIGRATE_SOURCE_ERROR_PARSE))?;
    Ok(Chosen {
        source: Source::Backup {
            router: router.to_owned(),
            name: name.to_owned(),
        },
        text,
    })
}

/// The startup configuration of `router` as the source.
///
/// # Errors
///
/// Returns the router field and its message for a router the user may not migrate, that
/// does not answer, or whose configuration does not parse.
// cancel-safe: reads only.
async fn from_router(services: Services<'_>, router: &str) -> Result<Chosen, (Field, MessageKey)> {
    if !services.permits(router).await {
        return Err((Field::Router, keys::WEB_MIGRATE_SOURCE_ERROR_ROUTER));
    }
    let unread = (Field::Router, keys::WEB_MIGRATE_SOURCE_ERROR_READ);
    let client = services
        .fleet()
        .registry()
        .client(router)
        .await
        .map_err(|_error| unread)?;
    let bytes = client
        .download_config(ConfigKind::Startup)
        .await
        .map_err(|error| {
            tracing::warn!(%error, router, "migration source: startup configuration not read");
            unread
        })?;
    let text = String::from_utf8(bytes.expose_secret().to_vec())
        .map(SecretString::from)
        .map_err(|_error| (Field::Router, keys::WEB_MIGRATE_SOURCE_ERROR_PARSE))?;
    parse_source(&text)
        .map(drop)
        .map_err(|_problem| (Field::Router, keys::WEB_MIGRATE_SOURCE_ERROR_PARSE))?;
    Ok(Chosen {
        source: Source::Router {
            router: router.to_owned(),
        },
        text,
    })
}

impl Chosen {
    /// Where the source came from and its text.
    pub(crate) fn into_parts(self) -> (Source, SecretString) {
        (self.source, self.text)
    }
}

/// The kind `form` chose and the source it read.
// cancel-safe: reads only.
pub(crate) async fn choose(
    services: Services<'_>,
    form: Submitted,
) -> (&'static str, Result<Chosen, (Field, MessageKey)>) {
    match form.kind.as_str() {
        "file" => ("file", from_file(form.file)),
        "backup" => ("backup", from_backup(services, &form.backup).await),
        "router" => ("router", from_router(services, &form.router).await),
        _ => (
            "router",
            Err((Field::Kind, keys::WEB_MIGRATE_SOURCE_ERROR_KIND)),
        ),
    }
}
