//! A stand-in for the running scheduler, recording what the page asked of it.

extern crate alloc;

use alloc::{collections::BTreeMap, sync::Arc};
use std::sync::{Mutex, PoisonError};

use kcc_app::permissions::Role;
use kcc_web::admin_scheduled::{
    Checked, RunNow, RunNowStarted, ScheduleControl, ScheduleDraft, ScheduleRefusal,
};

/// What the stub was asked: a check (role name and draft) or a run-now (role name, actor
/// and schedule id).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Asked {
    /// `check`.
    Check(String, ScheduleDraft),
    /// `run_now`.
    Run(String, String, String),
}

/// A stand-in for the running scheduler: fixed answers, and a record of what the page
/// asked of it.
#[derive(Debug, Default)]
pub(crate) struct Stub {
    /// The refusal `check` answers with; `None` lets every draft pass.
    check: Mutex<Option<ScheduleRefusal>>,
    /// The refusal `run_now` answers with; `None` admits every run.
    run: Mutex<Option<ScheduleRefusal>>,
    /// What `next_slots` reports.
    next: Mutex<BTreeMap<String, (String, i64)>>,
    /// What the page asked, in order.
    asked: Mutex<Vec<Asked>>,
}

impl Stub {
    /// A scheduler that lets every draft pass and admits every run.
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Makes `check` answer `refusal`.
    pub(crate) fn refuse_checks(&self, refusal: ScheduleRefusal) {
        *self.check.lock().unwrap_or_else(PoisonError::into_inner) = Some(refusal);
    }

    /// Makes `run_now` answer `refusal`.
    pub(crate) fn refuse_runs(&self, refusal: ScheduleRefusal) {
        *self.run.lock().unwrap_or_else(PoisonError::into_inner) = Some(refusal);
    }

    /// Reports `name`'s next slot `slot` on `router`.
    pub(crate) fn plan(&self, router: &str, name: &str, slot: i64) {
        drop(
            self.next
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(router.to_owned(), (name.to_owned(), slot)),
        );
    }

    /// What the page asked, in order.
    pub(crate) fn asked(&self) -> Vec<Asked> {
        self.asked
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Records `asked`.
    fn record(&self, asked: Asked) {
        self.asked
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(asked);
    }
}

impl ScheduleControl for Stub {
    fn check<'call>(&'call self, role: &'call Role, draft: &'call ScheduleDraft) -> Checked<'call> {
        self.record(Asked::Check(role.name.clone(), draft.clone()));
        let answer = *self.check.lock().unwrap_or_else(PoisonError::into_inner);
        Box::pin(async move { answer.map_or(Ok(None), Err) })
    }

    fn run_now<'call>(
        &'call self,
        role: &'call Role,
        actor: &'call str,
        id: &'call str,
    ) -> RunNow<'call> {
        self.record(Asked::Run(
            role.name.clone(),
            actor.to_owned(),
            id.to_owned(),
        ));
        let answer = *self.run.lock().unwrap_or_else(PoisonError::into_inner);
        Box::pin(async move { answer.map_or(Ok(RunNowStarted::new()), Err) })
    }

    fn next_slots(&self) -> BTreeMap<String, (String, i64)> {
        self.next
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}
