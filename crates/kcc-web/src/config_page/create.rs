//! A backup created from the router's saved configuration, and a backup deleted.

use core::str;

use axum::{
    Form,
    extract::{Path, Query, State},
    http::HeaderMap,
    response::Response,
};
use fluent_bundle::FluentArgs;
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_rci::ConfigKind;
use secrecy::{ExposeSecret as _, SecretString};
use serde::Deserialize;
use serde_json::Value;

use super::{
    backup_rows::{MANUAL, stamp},
    confirm::{self, ConfirmDialog},
    page::Visit,
    store::{self, CREATE, DELETE, Opened, StoreError},
};
use crate::{
    WebState,
    authz::CurrentUser,
    page_kit::{
        confirm::Gate,
        failure::rci_failure,
        family::Family,
        outcome::{Failure, Outcome},
        request::{missing, with_query},
        respond::Answer,
    },
};

/// The backup a request names.
#[derive(Debug, Deserialize)]
pub(crate) struct Named {
    /// The backup's file name.
    name: String,
}

impl Named {
    /// The backup's file name.
    pub(crate) fn name(&self) -> &str {
        &self.name
    }
}

/// `POST /ui/r/{router}/config/backups`: a backup of the router's saved configuration.
///
/// # Errors
///
/// Answers 404, 503 or the audited 403 when the router, the store or the permission is
/// missing.
// NOT cancel-safe: the backup may be written, and its audit entry queued, after the future is
// dropped.
pub(crate) async fn create(
    State(state): State<WebState>,
    Path(router): Path<String>,
    headers: HeaderMap,
    user: CurrentUser,
) -> Result<Response, Answer> {
    let opened = CREATE.open(&state, &user, &router).await?;
    let visit = Visit::new(&state, &user, &router);
    let locale = user.locale();
    let text = match saved(&state, &router, locale).await {
        Ok(found) => found,
        Err(failure) => return Ok(stopped(opened, failure, &headers).await),
    };
    let outcome = match store::keep(opened.services(), &router, (MANUAL.to_owned(), text)).await {
        Ok(info) => {
            opened.finish((&info.name, Value::Null), "success").await;
            Outcome::done(tr(locale, keys::WEB_CONFIG_BACKUP_CREATED, None), false)
        }
        Err(error) => return Ok(stopped(opened, stored(locale, error), &headers).await),
    };
    Ok(visit.answer_backups(outcome, &headers).await)
}

/// `POST /ui/r/{router}/config/backups/delete?name=`: asks for the router name, then
/// deletes the backup.
///
/// # Errors
///
/// Answers 404 for an unknown backup, and 404, 503 or the audited 403 when the router,
/// the store or the permission is missing; a store that cannot be listed stops the delete
/// in the outcome, audited.
// NOT cancel-safe: the backup file may be removed, and its audit entry queued, after the future is
// dropped.
pub(crate) async fn delete(
    State(state): State<WebState>,
    Path(router): Path<String>,
    Query(named): Query<Named>,
    headers: HeaderMap,
    user: CurrentUser,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let opened = DELETE.open(&state, &user, &router).await?;
    let visit = Visit::new(&state, &user, &router);
    let locale = user.locale();
    let listed = match store::list(opened.services(), &router).await {
        Ok(found) => found,
        Err(error) => return Ok(stopped(opened, stored(locale, error), &headers).await),
    };
    let Some(info) = listed.into_iter().find(|info| info.name == named.name) else {
        return Err(missing());
    };
    if let Gate::Ask { wrong_name } = confirm::gate(&pairs, &router) {
        let mut args = FluentArgs::new();
        args.set("router", router.clone());
        args.set("name", stamp(info.created_at).1);
        let words = (
            keys::WEB_CONFIG_DELETE_TITLE,
            keys::WEB_CONFIG_DELETE_TEXT,
            keys::COMMON_DELETE,
        );
        let action = with_query(
            &format!("/ui/r/{router}/config/backups/delete"),
            &[("name", &info.name)],
        );
        return Ok(ConfirmDialog::new(locale, action, (words, &args)).ask(wrong_name, &router));
    }
    let outcome = match store::delete(opened.services(), &router, &info.name).await {
        Ok(()) => {
            opened.finish((&info.name, Value::Null), "success").await;
            Outcome::done(tr(locale, keys::WEB_CONFIG_BACKUP_DELETED, None), false)
        }
        Err(error) => return Ok(stopped(opened, stored(locale, error), &headers).await),
    };
    Ok(visit.answer_backups(outcome, &headers).await)
}

/// The router's saved configuration, as text.
///
/// # Errors
///
/// Returns why it could not be read, the router's own words kept.
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, reads only.
async fn saved(state: &WebState, router: &str, locale: Locale) -> Result<SecretString, Failure> {
    let unreachable = || Failure::new(tr(locale, keys::WEB_KIT_UNREACHABLE, None), "unreachable");
    let fleet = state.fleet().ok_or_else(unreachable)?;
    let client = fleet.registry().client(router).await.map_err(|error| {
        tracing::warn!(%error, router, "backup: no router client");
        unreachable()
    })?;
    let bytes = client
        .download_config(ConfigKind::Startup)
        .await
        .map_err(|error| rci_failure(Family::Changes, locale, &error))?;
    let text = str::from_utf8(bytes.expose_secret()).map_err(|_error| {
        Failure::new(
            tr(locale, keys::WEB_CONFIG_NOT_TEXT, None),
            "invalid_response",
        )
    })?;
    Ok(SecretString::from(text.to_owned()))
}

/// The failure of a store that refused.
pub(crate) fn stored(locale: Locale, error: StoreError) -> Failure {
    match error {
        StoreError::Missing => {
            Failure::new(tr(locale, keys::WEB_CONFIG_DIFF_MISSING, None), "not_found")
        }
        StoreError::Failed => {
            Failure::new(tr(locale, keys::WEB_CONFIG_STORE_FAILED, None), "failed")
        }
    }
}

/// The answer to an action `failure` stopped, audited.
// NOT cancel-safe: an abandoned append may still be written.
async fn stopped(opened: Opened<'_>, failure: Failure, headers: &HeaderMap) -> Response {
    let visit = Visit::new(opened.state(), opened.user(), opened.router());
    opened
        .finish(("backups", Value::Null), failure.audit())
        .await;
    visit
        .answer_backups(Outcome::failed(failure), headers)
        .await
}
