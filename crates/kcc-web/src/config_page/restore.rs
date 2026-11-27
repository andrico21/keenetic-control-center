//! Restoring a backup: through the migration wizard, which reviews the plan before
//! anything is sent, or as a raw restore of the same router model.
//!
//! The wizard is reached through one link, [`migrate_restore_url`]. A raw restore needs
//! `Destructive` and `Migrate` and the router name typed; a backup of another model, or
//! one that does not name its model or firmware, is refused before anything is asked or
//! sent. The restore then runs as its own task through the migration applier
//! (`raw::run`); the request waits for it up to [`RAW_WAIT`] and the task audits its end
//! either way.

use core::time::Duration;

use axum::{
    Form,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse as _, Response},
};
use fluent_bundle::FluentArgs;
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_migrate::source::SourceConfig;
use kcc_rci::SecretBytes;
use secrecy::ExposeSecret as _;
use serde_json::Value;
use tokio::time::timeout;

use super::{
    backup_rows::stamp,
    confirm::{self, ConfirmDialog},
    create::{Named, stored},
    raw::{self, RawFailure, RawJob},
    store::{self, Opened, RAW_RESTORE, StoreError},
};
use crate::{
    WebState,
    authz::CurrentUser,
    page_kit::{
        audit::Record,
        confirm::Gate,
        context,
        family::Family,
        outcome::{Failure, Outcome},
        read_failure::ReadProblem,
        request::with_query,
        respond::{Answer, changed},
    },
};

/// Path of the migration wizard, which a raw restore points to.
const WIZARD: &str = "/ui/migrate";

/// Whether this build serves the migration wizard at [`WIZARD`].
///
/// `tests/config_pages` probes the route and fails while the two disagree; when this is
/// `false` the page says that restoring through the wizard is not available.
pub(crate) const WIZARD_SERVED: bool = true;

/// How long the request waits for a raw restore; the restore goes on after that.
const RAW_WAIT: Duration = Duration::from_secs(25);

/// The one link into the migration wizard: it restores `backup` of `router` onto the
/// same router.
pub(crate) fn migrate_restore_url(router: &str, backup: &str) -> String {
    with_query(
        WIZARD,
        &[
            ("source", "backup"),
            ("router", router),
            ("backup", backup),
            ("target", router),
        ],
    )
}

/// `POST /ui/r/{router}/config/backups/raw-restore?name=`: checks the backup's model,
/// asks for the router name, then restores the backup as the router's saved
/// configuration and restarts the router.
///
/// # Errors
///
/// Answers 404 for an unknown backup, and 404, 503 or the audited 403 when the router,
/// the store or the permission is missing.
// NOT cancel-safe: once spawned, the restore task replaces the router's saved configuration and
// audits itself whether or not this future is still awaited; before that, a refusal queues an audit
// entry that may be written after the drop.
pub(crate) async fn raw_restore(
    State(state): State<WebState>,
    Path(router): Path<String>,
    Query(named): Query<Named>,
    user: CurrentUser,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let opened = RAW_RESTORE.open(&state, &user, &router).await?;
    let (name, locale) = (named.name(), user.locale());
    let text = match store::read(opened.services(), &router, name).await {
        Ok(found) => found,
        Err(StoreError::Missing) => {
            let gone = StatusCode::NOT_FOUND.into_response();
            return Err(opened.refuse(name, "not_found", gone).await);
        }
        Err(error) => return Ok(stop(opened, name, stored(locale, error)).await),
    };
    let model = match context::target(&state, &user, &router).await {
        Ok(target) => target
            .facts(&state)
            .await
            .map(|facts| facts.hw_id().map(str::to_owned)),
        Err(refusal) => return Err(refusal.status().into()),
    };
    let checked = model
        .map_err(|error| {
            error
                .problem(Family::Changes)
                .failure(locale, "unreachable")
        })
        .and_then(|found| {
            let shown = state.router_name(&router);
            same_model(text.expose_secret(), found.as_deref(), (&shown, locale))
        });
    if let Err(failure) = checked {
        return Ok(stop(opened, name, failure).await);
    }
    if let Gate::Ask { wrong_name } = confirm::gate(&pairs, &router) {
        return Ok(ask(&opened, name, wrong_name).await);
    }
    let bytes = SecretBytes::from(text.expose_secret().as_bytes().to_vec());
    let Some(job) = RawJob::new(&opened, bytes) else {
        let failure = Failure::new(tr(locale, keys::WEB_KIT_UNREACHABLE, None), "unreachable");
        return Ok(stop(opened, name, failure).await);
    };
    let record = Record::on_router(RAW_RESTORE.action(), &router, name.to_owned());
    let (task_state, task_user) = (state.clone(), user.clone());
    let task = tokio::spawn(async move {
        let result = raw::run(job).await;
        let ended = match &result {
            Ok(()) => "success",
            Err(failure) => failure.failure(locale).audit(),
        };
        record.append(&task_state, &task_user, ended).await;
        result
    });
    let outcome = match timeout(RAW_WAIT, task).await {
        Ok(Ok(Ok(()))) => Outcome::done(tr(locale, keys::WEB_CONFIG_RAW_DONE, None), false),
        Ok(Ok(Err(failure))) => Outcome::failed(failure.failure(locale)),
        Ok(Err(error)) => {
            tracing::error!(%error, "raw restore task failed");
            let unknown = RawFailure::Router(ReadProblem::from(Family::Changes.unreachable()));
            Outcome::failed(unknown.failure(locale))
        }
        Err(_elapsed) => Outcome::info(tr(locale, keys::WEB_CONFIG_RAW_PENDING, None), "pending"),
    };
    Ok(changed(outcome, None, None, locale))
}

/// Whether the backup `text` can be restored raw onto a router of `model`, shown as
/// `named`: it must name the same model and the firmware it was saved on.
///
/// # Errors
///
/// Returns why not, naming both models.
fn same_model(
    text: &str,
    model: Option<&str>,
    (named, locale): (&str, Locale),
) -> Result<(), Failure> {
    let Ok(source) = SourceConfig::from_bytes(text.as_bytes()) else {
        return Err(RawFailure::Unreadable.failure(locale));
    };
    let mut args = FluentArgs::new();
    args.set("router", named.to_owned());
    args.set("value", model.unwrap_or_default().to_owned());
    let key = match (source.hw_id.as_deref(), model) {
        (Some(saved), Some(actual)) if saved.eq_ignore_ascii_case(actual) => {
            if source.firmware.is_some() {
                return Ok(());
            }
            keys::WEB_CONFIG_RAW_FIRMWARE_UNKNOWN
        }
        (Some(saved), _) => {
            args.set("model", saved.to_owned());
            keys::WEB_CONFIG_RAW_MODEL
        }
        (None, _) => keys::WEB_CONFIG_RAW_MODEL_UNKNOWN,
    };
    Err(Failure::new(
        tr(locale, key, Some(&args)),
        "hardware_mismatch",
    ))
}

/// The confirmation of the raw restore of the backup `name`.
// cancel-safe: reads only.
async fn ask(opened: &Opened<'_>, name: &str, wrong_name: bool) -> Response {
    let router = opened.router();
    let mut args = FluentArgs::new();
    args.set("router", opened.state().router_name(router));
    args.set("id", router.to_owned());
    let listed = store::list(opened.services(), router)
        .await
        .unwrap_or_default();
    let when = listed
        .iter()
        .find(|info| info.name == name)
        .map_or_else(|| name.to_owned(), |info| stamp(info.created_at).1);
    args.set("name", when);
    let words = (
        keys::WEB_CONFIG_RAW_TITLE,
        keys::WEB_CONFIG_RAW_TEXT,
        keys::WEB_CONFIG_RAW_RESTORE,
    );
    let action = with_query(
        &format!("/ui/r/{router}/config/backups/raw-restore"),
        &[("name", name)],
    );
    ConfirmDialog::new(opened.user().locale(), action, (words, &args)).ask(wrong_name, router)
}

/// The answer to a raw restore `failure` stopped before anything was sent, audited.
// NOT cancel-safe: an abandoned append may still be written.
async fn stop(opened: Opened<'_>, name: &str, failure: Failure) -> Response {
    let locale = opened.user().locale();
    opened.finish((name, Value::Null), failure.audit()).await;
    changed(Outcome::failed(failure), None, None, locale)
}
