//! The end of an apply nobody finishes: the router's recovery timer runs out, the router
//! restores its startup configuration on its own, and kcc lets go of the target.
//!
//! The settler hands the applier to the run's live view and starts one [`expire`] per
//! apply. Once the timer's window has passed, it drops the applier (which releases the
//! router's write lease), frees the target and ends the run as rolled back by the
//! router; a choice made before then has taken the applier, and nothing happens.

use alloc::sync::Arc;
use core::time::Duration;

use tokio::time::sleep;

use super::{
    finishing::Finishing,
    live::Live,
    service::{Session, Wizards},
    services::Services,
};
use crate::{WebState, authz::CurrentUser};

/// The apply an [`expire`] watches.
pub(crate) struct Watched<F>
where
    F: Finishing,
{
    /// Web services, for the time and the run's files.
    state: WebState,
    /// Who started the apply.
    user: CurrentUser,
    /// The wizards, to free the target.
    wizards: Arc<Wizards<F>>,
    /// The run's session, for its turn.
    session: Arc<Session<F>>,
    /// The apply.
    live: Arc<Live>,
    /// The run id.
    id: String,
    /// The target router.
    target: String,
}

impl<F> Watched<F>
where
    F: Finishing,
{
    /// The apply `live` of run `id` on `target`, started by `user`, whose run keeps
    /// `session` in `wizards`.
    pub(crate) fn new(
        (state, user): (WebState, CurrentUser),
        (wizards, session, live): (Arc<Wizards<F>>, Arc<Session<F>>, Arc<Live>),
        (id, target): (String, String),
    ) -> Self {
        Self {
            state,
            user,
            wizards,
            session,
            live,
            id,
            target,
        }
    }
}

/// Waits `left`, the rest of the router's recovery window, then ends the apply of
/// `watched` unless a choice ended it first.
// NOT cancel-safe: the record write may be abandoned; cancelled while waiting, the
// applier stays where it was.
pub(crate) async fn expire<F>(watched: Watched<F>, left: Duration)
where
    F: Finishing,
{
    sleep(left).await;
    let Watched {
        state,
        user,
        wizards,
        session,
        live,
        id,
        target,
    } = watched;
    let _turn = session.turn().await;
    if !session
        .live()
        .is_some_and(|current| Arc::ptr_eq(&current, &live))
    {
        return;
    }
    let Some(applier) = live.applier().await.take() else {
        return;
    };
    drop(applier);
    session.set_live(None);
    wizards.release(&target, &id);
    tracing::warn!(
        id,
        target,
        "apply not finished in the recovery window; released"
    );
    end::<F>(&state, &user, &id);
}

/// Ends run `id`, started by `user`, as rolled back by the router, and deletes what it
/// sealed for its apply.
fn end<F>(state: &WebState, user: &CurrentUser, id: &str)
where
    F: Finishing,
{
    let Ok(services) = Services::of(state, user) else {
        return;
    };
    let store = services.store();
    match store.load::<F>(id) {
        Ok(Some(mut record)) => {
            record.finish(F::ROLLED_BACK_BY_ROUTER, state.unix_seconds());
            if let Err(error) = store.save(&record) {
                tracing::error!(%error, "expired apply could not be recorded");
            }
            F::discard(services, id);
        }
        Ok(None) => tracing::error!(id, "run record missing at its apply's expiry"),
        Err(error) => tracing::error!(%error, "run record unreadable at its apply's expiry"),
    }
}
