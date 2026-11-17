//! Step 1 of a migration, with the panel of `crate::wizard::source`.
//!
//! The text must parse as a router configuration (its checksum too); it is sealed beside
//! the record, which only names where it came from. The form is `multipart/form-data`
//! because of the file; the route's body limit is 1 MiB, and a larger upload is answered
//! with the localized size error beside the file input.

use alloc::sync::Arc;

use axum::{
    Extension,
    extract::{Multipart, Path, State, multipart::MultipartRejection},
    response::Response,
};
use kcc_i18n::keys;
use serde_json::json;

use super::{
    access::{Migration as _, Visit},
    kinds::{Mode, Step},
    record::Record,
};
use crate::{
    WebState,
    authz::CurrentUser,
    errors,
    page_kit::{
        audit::Record as Audit,
        context::{Refusal, fragment_shell},
        respond::Answer,
    },
    wizard::{
        flow::Flow as _,
        screen,
        service::Wizards,
        services::Services,
        source::{Field, Panel, refuse},
        source_read,
    },
};

/// `POST /ui/migrate/{id}/source`: reads and checks the chosen source, seals it and moves
/// on to the target.
///
/// # Errors
///
/// Answers the refusal of the migration, and the panel with its field error (422).
// NOT cancel-safe: the sealed source and the run record may be written, the stored passwords
// deleted, and the audit entry queued, after the future is dropped.
pub(super) async fn submit(
    State(state): State<WebState>,
    Path(id): Path<String>,
    Extension(wizards): Extension<Arc<Wizards<Record>>>,
    user: CurrentUser,
    multipart: Result<Multipart, MultipartRejection>,
) -> Result<Response, Answer> {
    let services = Services::of(&state, &user).map_err(Refusal::status)?;
    let mut visit = Visit::open(services, &wizards, &id)
        .await
        .map_err(Refusal::status)?;
    let session = visit.session();
    if visit.record().step() != Step::Source || visit.record().mode() == Mode::Restore {
        return Ok(screen::moved(visit.record()));
    }
    let locale = user.locale();
    let panel = Panel::posting(services, format!("/ui/migrate/{id}/source"), None).await;
    let submitted = match multipart {
        Ok(fields) => source_read::read(fields).await,
        Err(_rejection) => Err(keys::WEB_MIGRATE_SOURCE_ERROR_FILE),
    };
    let form = match submitted {
        Ok(found) => found,
        Err(message) => {
            return Err(refuse(panel, "file", Field::File, message, locale));
        }
    };
    let (kind, chosen) = source_read::choose(services, form).await;
    let (source, text) = match chosen {
        Ok(found) => found.into_parts(),
        Err((field, message)) => return Err(refuse(panel, kind, field, message, locale)),
    };
    if let Err(error) = visit.seal_source(&text).await {
        return Err(errors::internal(&error, fragment_shell(locale)).into());
    }
    let router = source.router().map(str::to_owned);
    visit.record_mut().choose_source(source);
    session.forget();
    if let Err(error) = visit.forget_passwords().await {
        return Err(errors::internal(&error, fragment_shell(locale)).into());
    }
    if let Err(error) = visit.save().await {
        return Err(errors::internal(&error, fragment_shell(locale)).into());
    }
    let audit = match router {
        Some(found) => Audit::on_router("web.migrate_source", &found, id),
        None => Audit::new("web.migrate_source", id),
    };
    audit
        .with_params(json!({ "kind": kind }))
        .append(&state, &user, "chosen")
        .await;
    Ok(screen::moved(visit.record()))
}
