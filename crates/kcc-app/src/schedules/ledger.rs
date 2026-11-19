//! The run ledger: at most one run per slot, and the outcome of the last runs.
//!
//! `schedule_runs.json` is written only by kcc. Every change is one locked
//! read-modify-write, so two processes racing for one slot cannot both begin it.

extern crate alloc;

use alloc::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::store::SchedulesDocument;
use crate::persist::{Edit, Migration, StateDoc, StateError, StateStore};

/// Runs kept per schedule; older ones are dropped.
const KEPT_RUNS: usize = 20;

/// Run history per schedule id, as stored in `schedule_runs.json`.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct RunsDocument {
    /// Per schedule id.
    pub schedules: BTreeMap<String, ScheduleRuns>,
}

impl StateDoc for RunsDocument {
    const FILE_NAME: &'static str = "schedule_runs.json";
    const SCHEMA: u32 = 1;
    const MIGRATIONS: &'static [Migration] = &[];
}

/// The run history of one schedule.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ScheduleRuns {
    /// No slot at or before this instant (Unix seconds) fires.
    pub last_fired_slot: Option<i64>,
    /// The last runs, oldest first.
    pub runs: Vec<RunRecord>,
}

/// One run.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct RunRecord {
    /// The slot, Unix seconds; `None` for a run-now.
    pub slot: Option<i64>,
    /// Where the run stands.
    pub state: RunState,
    /// The background job that carried it out, once known.
    pub job_id: Option<String>,
    /// Unix seconds.
    pub started_at: i64,
    /// Unix seconds; `None` while started.
    pub finished_at: Option<i64>,
    /// Who asked for a run-now, in audit form.
    pub requested_by: Option<String>,
}

/// Where a run stands.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum RunState {
    /// Recorded before the first router request.
    Started,
    /// Done.
    Succeeded {
        /// The run left changes the router has not saved.
        unsaved: bool,
        /// The router's `show last-change` checksum read right after the run.
        checksum: Option<String>,
    },
    /// Failed with a machine-read code.
    Failed {
        /// Error code.
        code: String,
    },
    /// Not carried out, with a machine-read reason.
    Skipped {
        /// Reason code.
        reason: String,
    },
    /// Found started when a server started; reported once and never run again.
    Interrupted,
}

/// How a begun run ended.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RunOutcome {
    /// See [`RunState::Succeeded`].
    Succeeded {
        /// See [`RunState::Succeeded`].
        unsaved: bool,
        /// See [`RunState::Succeeded`].
        checksum: Option<String>,
    },
    /// See [`RunState::Failed`].
    Failed {
        /// See [`RunState::Failed`].
        code: String,
    },
    /// See [`RunState::Skipped`].
    Skipped {
        /// See [`RunState::Skipped`].
        reason: String,
    },
}

impl From<RunOutcome> for RunState {
    #[inline]
    fn from(outcome: RunOutcome) -> Self {
        match outcome {
            RunOutcome::Succeeded { unsaved, checksum } => Self::Succeeded { unsaved, checksum },
            RunOutcome::Failed { code } => Self::Failed { code },
            RunOutcome::Skipped { reason } => Self::Skipped { reason },
        }
    }
}

/// What starts a run.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Trigger {
    /// A weekly slot, Unix seconds.
    Slot(i64),
    /// An explicit run-now, never refused by the ledger.
    Now {
        /// Who asked, in audit form.
        requested_by: String,
    },
}

/// The latest scheduled change a router has not saved.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct UnsavedRun {
    /// The schedule's id.
    pub schedule_id: String,
    /// The schedule's name.
    pub name: String,
    /// Unix seconds.
    pub finished_at: i64,
    /// The router's `show last-change` checksum read right after the run.
    pub checksum: Option<String>,
}

/// A refused or failed ledger operation.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RunError {
    /// The slot is at or before the last fired slot.
    #[error("slot already fired")]
    AlreadyFired,
    /// No started or interrupted run of the schedule began at that time.
    #[error("run not found")]
    NotFound,
    /// State storage failed.
    #[error(transparent)]
    State(#[from] StateError),
}

/// The run ledger in the state directory.
#[derive(Clone, Debug)]
#[non_exhaustive]
#[expect(
    clippy::module_name_repetitions,
    reason = "the executor and front ends name the ledger unqualified next to the store"
)]
pub struct RunLedger {
    /// The state directory.
    state: StateStore,
}

impl RunLedger {
    /// The ledger of `state`.
    #[must_use]
    #[inline]
    pub const fn new(state: StateStore) -> Self {
        Self { state }
    }

    /// Records a `Started` run of schedule `id` and, for a slot, marks the slot fired, in
    /// one locked update persisted before the caller sends any router request. Call it
    /// once per slot. Returns `now`, the run's `started_at`.
    ///
    /// # Errors
    ///
    /// [`RunError::AlreadyFired`] for a slot at or before the last fired slot (a run-now
    /// is never refused), or [`RunError::State`].
    #[inline]
    pub fn begin(&self, id: &str, trigger: Trigger, now: i64) -> Result<i64, RunError> {
        self.state.update_if_changed(|doc: &mut RunsDocument| {
            let runs = doc.schedules.entry(id.to_owned()).or_default();
            let (slot, requested_by) = match trigger {
                Trigger::Slot(slot) => {
                    if runs.last_fired_slot.is_some_and(|fired| slot <= fired) {
                        return Edit::Unchanged(Err(RunError::AlreadyFired));
                    }
                    runs.last_fired_slot = Some(slot);
                    (Some(slot), None)
                }
                Trigger::Now { requested_by } => (None, Some(requested_by)),
            };
            runs.push(RunRecord {
                slot,
                state: RunState::Started,
                job_id: None,
                started_at: now,
                finished_at: None,
                requested_by,
            });
            Edit::Changed(Ok(now))
        })?
    }

    /// Sets the final state of the latest run of `id` that began at `started_at`,
    /// whether it is still started or was marked interrupted meanwhile.
    ///
    /// # Errors
    ///
    /// [`RunError::NotFound`] when no such run is started or interrupted, or
    /// [`RunError::State`].
    #[inline]
    pub fn finish(
        &self,
        id: &str,
        started_at: i64,
        outcome: RunOutcome,
        job_id: Option<String>,
        now: i64,
    ) -> Result<(), RunError> {
        self.state.update_if_changed(|doc: &mut RunsDocument| {
            let open = doc.schedules.get_mut(id).and_then(|runs| {
                runs.runs.iter_mut().rev().find(|run| {
                    run.started_at == started_at
                        && matches!(run.state, RunState::Started | RunState::Interrupted)
                })
            });
            let Some(run) = open else {
                return Edit::Unchanged(Err(RunError::NotFound));
            };
            run.state = outcome.into();
            run.finished_at = Some(now);
            if job_id.is_some() {
                run.job_id = job_id;
            }
            Edit::Changed(Ok(()))
        })?
    }

    /// Marks every started run interrupted and returns each one's schedule id and slot,
    /// for a server start to report once.
    ///
    /// # Errors
    ///
    /// [`RunError::State`].
    #[inline]
    pub fn interrupt_started(&self, now: i64) -> Result<Vec<(String, Option<i64>)>, RunError> {
        Ok(self.state.update_if_changed(|doc: &mut RunsDocument| {
            let mut interrupted = Vec::new();
            for (id, runs) in &mut doc.schedules {
                for run in &mut runs.runs {
                    if run.state == RunState::Started {
                        run.state = RunState::Interrupted;
                        run.finished_at = Some(now);
                        interrupted.push((id.clone(), run.slot));
                    }
                }
            }
            if interrupted.is_empty() {
                Edit::Unchanged(interrupted)
            } else {
                Edit::Changed(interrupted)
            }
        })?)
    }

    /// Records slot `slot` of `id` as skipped for `reason` and marks it fired.
    ///
    /// # Errors
    ///
    /// [`RunError::AlreadyFired`] for a slot at or before the last fired slot, or
    /// [`RunError::State`].
    #[inline]
    pub fn skip(&self, id: &str, slot: i64, reason: &str, now: i64) -> Result<(), RunError> {
        self.state.update_if_changed(|doc: &mut RunsDocument| {
            let runs = doc.schedules.entry(id.to_owned()).or_default();
            if runs.last_fired_slot.is_some_and(|fired| slot <= fired) {
                return Edit::Unchanged(Err(RunError::AlreadyFired));
            }
            runs.last_fired_slot = Some(slot);
            runs.push(RunRecord {
                slot: Some(slot),
                state: RunState::Skipped {
                    reason: reason.to_owned(),
                },
                job_id: None,
                started_at: now,
                finished_at: Some(now),
                requested_by: None,
            });
            Edit::Changed(Ok(()))
        })?
    }

    /// The last runs of `id`, oldest first.
    ///
    /// # Errors
    ///
    /// [`RunError::State`].
    #[inline]
    pub fn runs(&self, id: &str) -> Result<Vec<RunRecord>, RunError> {
        Ok(self
            .state
            .read::<RunsDocument>()?
            .and_then(|mut doc| doc.schedules.remove(id))
            .map_or_default(|runs| runs.runs))
    }

    /// The latest successful run of a policy-switch or preset schedule of `router` that
    /// left unsaved changes.
    ///
    /// # Errors
    ///
    /// [`RunError::State`].
    #[inline]
    pub fn last_unsaved(&self, router: &str) -> Result<Option<UnsavedRun>, RunError> {
        let schedules = self.state.read::<SchedulesDocument>()?.unwrap_or_default();
        let runs = self.state.read::<RunsDocument>()?.unwrap_or_default();
        Ok(schedules
            .schedules
            .iter()
            .filter(|schedule| schedule.router == router && schedule.action.changes_configuration())
            .filter_map(|schedule| {
                let history = runs.schedules.get(&schedule.id)?;
                history
                    .runs
                    .iter()
                    .rev()
                    .find_map(|run| match (&run.state, run.finished_at) {
                        (
                            RunState::Succeeded {
                                unsaved: true,
                                checksum,
                            },
                            Some(finished_at),
                        ) => Some(UnsavedRun {
                            schedule_id: schedule.id.clone(),
                            name: schedule.name.as_str().to_owned(),
                            finished_at,
                            checksum: checksum.clone(),
                        }),
                        _ => None,
                    })
            })
            .max_by_key(|unsaved| unsaved.finished_at))
    }

    /// Drops the history of a deleted schedule.
    ///
    /// # Errors
    ///
    /// [`RunError::State`].
    #[inline]
    pub fn forget(&self, id: &str) -> Result<(), RunError> {
        Ok(self.state.update_if_changed(|doc: &mut RunsDocument| {
            if doc.schedules.remove(id).is_some() {
                Edit::Changed(())
            } else {
                Edit::Unchanged(())
            }
        })?)
    }

    /// Marks every slot of `id` up to `now` fired, so a created, edited or resumed
    /// schedule never runs a slot from before the change.
    ///
    /// # Errors
    ///
    /// [`StateError`].
    pub(super) fn fire_until(&self, id: &str, now: i64) -> Result<(), StateError> {
        self.state.update_if_changed(|doc: &mut RunsDocument| {
            let runs = doc.schedules.entry(id.to_owned()).or_default();
            if runs.last_fired_slot.is_some_and(|fired| fired >= now) {
                Edit::Unchanged(())
            } else {
                runs.last_fired_slot = Some(now);
                Edit::Changed(())
            }
        })
    }
}

impl ScheduleRuns {
    /// Appends `run`, dropping the oldest beyond the kept number.
    fn push(&mut self, run: RunRecord) {
        self.runs.push(run);
        let excess = self.runs.len().saturating_sub(KEPT_RUNS);
        drop(self.runs.drain(..excess));
    }
}
