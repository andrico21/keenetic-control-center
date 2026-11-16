//! How many runs a user keeps open and how long kcc keeps a run.
//!
//! A user keeps at most [`OPEN_RUNS`] unfinished runs of each wizard; another start is
//! refused. A run whose record has not changed for [`ABANDONED_AFTER`] counts as
//! abandoned and no longer as open, and a run whose record has not changed for
//! [`KEPT_FOR`] is deleted with everything kcc kept for it. The record's last change is
//! its file's modification time: every change writes the record, a page view does not.

use std::{fs, io, time::UNIX_EPOCH};

use axum::http::StatusCode;
use kcc_i18n::{bundle::tr, keys};
use serde_json::Value;

use super::{
    flow::Flow,
    ids::is_id,
    index,
    services::Services,
    store::{Store, StoreError},
};
use crate::{
    errors,
    page_kit::{
        audit::Record as Audit,
        context::fragment_shell,
        outcome::{Failure, Outcome, with_status},
        respond::Answer,
    },
};

/// Unfinished runs one user keeps of one wizard.
pub(crate) const OPEN_RUNS: usize = 10;

/// Seconds without a change after which an unfinished run counts as abandoned.
pub(crate) const ABANDONED_AFTER: u64 = 24 * 60 * 60;

/// Seconds without a change after which a run is deleted.
pub(crate) const KEPT_FOR: u64 = 30 * 24 * 60 * 60;

/// Whether `owner` may start another run of wizard `F` at Unix second `now`.
///
/// # Errors
///
/// Returns read failures of the index and the records.
pub(crate) fn may_start<F>(store: &Store, owner: &str, now: u64) -> Result<bool, StoreError>
where
    F: Flow,
{
    let mut open = 0_usize;
    for record in store.list::<F>(owner)? {
        let recent = changed::<F>(store, record.id())?
            .is_some_and(|at| now.saturating_sub(at) <= ABANDONED_AFTER);
        if recent && record.finished().is_none() {
            open = open.saturating_add(1);
        }
    }
    Ok(open < OPEN_RUNS)
}

/// Deletes, at Unix second `now`, every run of wizard `F` whose record has not changed
/// for [`KEPT_FOR`].
pub(crate) fn sweep<F>(store: &Store, now: u64)
where
    F: Flow,
{
    let runs = match index::runs::<F>(store) {
        Ok(found) => found,
        Err(error) => {
            tracing::warn!(%error, "runs could not be listed for deletion");
            return;
        }
    };
    let ended = runs
        .into_keys()
        .filter(|id| gone::<F>(store, id, now))
        .collect::<Vec<_>>();
    if let Err(error) = index::forget::<F>(store, &ended) {
        tracing::warn!(%error, "deleted runs could not be dropped from the index");
    }
}

/// Whether run `id` of wizard `F` is gone at Unix second `now`: its record is missing,
/// or the run was deleted because it had not changed for [`KEPT_FOR`].
fn gone<F>(store: &Store, id: &str, now: u64) -> bool
where
    F: Flow,
{
    match changed::<F>(store, id) {
        Ok(None) => true,
        Ok(Some(at)) if now.saturating_sub(at) > KEPT_FOR => match store.delete(id) {
            Ok(()) => true,
            Err(error) => {
                tracing::error!(%error, "an expired run could not be deleted");
                false
            }
        },
        Ok(Some(_)) => false,
        Err(error) => {
            tracing::warn!(%error, "a run's age could not be read");
            false
        }
    }
}

/// The Unix second the record of run `id` of wizard `F` last changed, `None` without
/// a record.
///
/// # Errors
///
/// Returns metadata read failures other than a missing record.
fn changed<F>(store: &Store, id: &str) -> Result<Option<u64>, StoreError>
where
    F: Flow,
{
    if !is_id(id) {
        return Ok(None);
    }
    let modified = match fs::metadata(store.root().join(id).join(F::FILE)) {
        Ok(metadata) => metadata.modified()?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    Ok(Some(
        modified
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| since.as_secs()),
    ))
}

/// The answer refusing a start of wizard `F` by the user of `services` at Unix second
/// `now` past [`OPEN_RUNS`] (422 with the reason, audited as `action` with `params`), or
/// `None` when the start may go on.
// NOT cancel-safe: the refusal's audit entry may be written after cancellation.
pub(crate) async fn refusal<F>(
    services: Services<'_>,
    now: u64,
    (action, params): (&'static str, Value),
) -> Option<Answer>
where
    F: Flow,
{
    let user = services.user();
    let locale = user.locale();
    match may_start::<F>(&services.store(), user.username(), now) {
        Ok(true) => None,
        Ok(false) => {
            Audit::new(action, String::new())
                .with_params(params)
                .append(services.state(), user, "refused")
                .await;
            let failure = Failure::new(tr(locale, keys::WEB_WIZARD_RUNS_LIMIT, None), "refused");
            let refused = Outcome::failed(failure).render(locale);
            Some(with_status(refused, StatusCode::UNPROCESSABLE_ENTITY).into())
        }
        Err(error) => Some(errors::internal(&error, fragment_shell(locale)).into()),
    }
}
