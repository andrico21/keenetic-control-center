//! What other pages say about scheduled actions: the dashboard's next scheduled action of
//! a router, and the configuration page's note on a scheduled change the router has not
//! saved.

use core::fmt;

use fluent_bundle::FluentArgs;
use kcc_app::{
    persist::StateStore,
    schedules::{ledger::RunLedger, store::SchedulesDocument, time::format_local},
};
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use tokio::task::spawn_blocking;

use crate::WebState;

/// "Next scheduled action: <name>, <time>" for `router` in `locale`, when the running
/// scheduler has an active schedule on it; the time is in the schedule's zone.
// cancel-safe: it only reads local state on a blocking thread.
pub(crate) async fn line(state: &WebState, router: &str, locale: Locale) -> Option<String> {
    let (name, slot) = state.schedules()?.next_slots().remove(router)?;
    let store = state.fleet()?.workflow().state().clone();
    let (owner, wanted) = (router.to_owned(), name.clone());
    let zone = read(move || {
        logged(store.read::<SchedulesDocument>())?
            .schedules
            .into_iter()
            .find(|schedule| schedule.router == owner && schedule.name.as_str() == wanted)
            .map(|schedule| schedule.when.zone().clone())
    })
    .await?;
    let mut args = FluentArgs::new();
    args.set("name", name);
    args.set("time", format_local(slot, &zone));
    Some(tr(locale, keys::WEB_SCHEDULED_NEXT, Some(&args)))
}

/// The note on the scheduled change `router` has not saved, in `locale`.
///
/// "Unsaved change from scheduled action <name> at <time>; a router restart undoes it",
/// when the latest scheduled change that left the router unsaved recorded `checksum`, the
/// router's current `show last-change` checksum.
// cancel-safe: it only reads local state on a blocking thread.
pub(crate) async fn unsaved_note(
    store: StateStore,
    router: &str,
    checksum: &str,
    locale: Locale,
) -> Option<String> {
    let (owner, current) = (router.to_owned(), checksum.to_owned());
    let (name, at, zone) = read(move || {
        let run = logged(RunLedger::new(store.clone()).last_unsaved(&owner))?;
        if run.checksum.as_deref() != Some(current.as_str()) {
            return None;
        }
        let zone = logged(store.read::<SchedulesDocument>())?
            .schedules
            .into_iter()
            .find(|schedule| schedule.id == run.schedule_id)?
            .when
            .zone()
            .clone();
        Some((run.name, run.finished_at, zone))
    })
    .await?;
    let mut args = FluentArgs::new();
    args.set("name", name);
    args.set("time", format_local(at, &zone));
    Some(tr(locale, keys::WEB_SCHEDULED_UNSAVED, Some(&args)))
}

/// Runs `work` on a blocking thread; a failed task reads as nothing, logged.
// cancel-safe: the work only reads and runs whole on its thread even if the future is dropped.
async fn read<T, F>(work: F) -> Option<T>
where
    T: Send + 'static,
    F: FnOnce() -> Option<T> + Send + 'static,
{
    spawn_blocking(work)
        .await
        .inspect_err(|error| tracing::warn!(%error, "scheduled actions could not be read"))
        .ok()
        .flatten()
}

/// The value of `read`, or nothing when it failed, logged.
fn logged<T, E>(read: Result<Option<T>, E>) -> Option<T>
where
    E: fmt::Display,
{
    read.unwrap_or_else(|error| {
        tracing::warn!(%error, "scheduled actions could not be read");
        None
    })
}
