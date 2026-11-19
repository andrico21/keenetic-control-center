//! Role-checked storage of scheduled actions in `schedules.json`.
//!
//! Every change is one locked read-modify-write of the document, so concurrent writers
//! cannot interleave; a create, edit or resume then marks the slots up to that moment
//! fired in the run ledger.

use serde::{Deserialize, Serialize};

use self::{
    access::{authorize, require_manage, visible},
    limits::admit,
};
use super::{
    ledger::{RunError, RunLedger},
    model::{Edit, NewSchedule, Owner, PauseReason, Schedule, ScheduleState, random_id},
};
use crate::{
    permissions::Role,
    persist::{self, Migration, StateDoc, StateError, StateStore},
};

mod access;
mod limits;

/// Most schedules on one router.
pub const MAX_PER_ROUTER: usize = 64;
/// Most schedules in total.
pub const MAX_TOTAL: usize = 256;

/// Every schedule, as stored in `schedules.json`.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct SchedulesDocument {
    /// The schedules, in creation order.
    pub schedules: Vec<Schedule>,
}

impl StateDoc for SchedulesDocument {
    const FILE_NAME: &'static str = "schedules.json";
    const SCHEMA: u32 = 1;
    const MIGRATIONS: &'static [Migration] = &[];
}

/// A refused or failed schedule operation.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ScheduleError {
    /// The role lacks `ManageSchedules` or a permission the action needs.
    #[error("schedule operation is forbidden")]
    Forbidden,
    /// No such schedule, or one on a router outside the role's scope.
    #[error("schedule was not found")]
    NotFound,
    /// The router already has a schedule of that name.
    #[error("schedule name is taken on this router")]
    DuplicateName,
    /// The router already has [`MAX_PER_ROUTER`] schedules.
    #[error("router has the most schedules allowed")]
    RouterLimit,
    /// There are already [`MAX_TOTAL`] schedules.
    #[error("the most schedules allowed exist")]
    TotalLimit,
    /// The operating system yielded no random bytes for an id.
    #[error("no schedule id available")]
    IdUnavailable,
    /// State storage failed.
    #[error(transparent)]
    State(#[from] StateError),
}

/// Scheduled actions in the state directory.
#[derive(Clone, Debug)]
#[non_exhaustive]
#[expect(
    clippy::module_name_repetitions,
    reason = "the public store type identifies the schedule domain"
)]
pub struct ScheduleStore {
    /// The state directory.
    state: StateStore,
    /// The run ledger in the same directory.
    ledger: RunLedger,
}

impl ScheduleStore {
    /// The schedules of `state`.
    #[must_use]
    #[inline]
    pub fn new(state: StateStore) -> Self {
        Self {
            ledger: RunLedger::new(state.clone()),
            state,
        }
    }

    /// Every schedule on a router in the role's scope.
    ///
    /// # Errors
    ///
    /// [`ScheduleError::Forbidden`] without `ManageSchedules`, or [`ScheduleError::State`].
    #[inline]
    pub fn list(&self, role: &Role) -> Result<Vec<Schedule>, ScheduleError> {
        require_manage(role)?;
        let doc = self.state.read::<SchedulesDocument>()?.unwrap_or_default();
        Ok(doc
            .schedules
            .into_iter()
            .filter(|schedule| visible(role, schedule))
            .collect())
    }

    /// One schedule on a router in the role's scope.
    ///
    /// # Errors
    ///
    /// [`ScheduleError::Forbidden`] without `ManageSchedules`, [`ScheduleError::NotFound`]
    /// (also outside the scope), or [`ScheduleError::State`].
    #[inline]
    pub fn get(&self, role: &Role, id: &str) -> Result<Schedule, ScheduleError> {
        require_manage(role)?;
        self.state
            .read::<SchedulesDocument>()?
            .unwrap_or_default()
            .schedules
            .into_iter()
            .find(|schedule| schedule.id == id && visible(role, schedule))
            .ok_or(ScheduleError::NotFound)
    }

    /// Creates an active schedule owned by `owner`.
    ///
    /// # Errors
    ///
    /// [`ScheduleError::Forbidden`] without `ManageSchedules` or the action's permissions
    /// on the router (and on a preset's source router), [`ScheduleError::DuplicateName`],
    /// [`ScheduleError::RouterLimit`], [`ScheduleError::TotalLimit`],
    /// [`ScheduleError::IdUnavailable`], or [`ScheduleError::State`].
    #[inline]
    pub fn create(
        &self,
        role: &Role,
        new: NewSchedule,
        owner: Owner,
        now: i64,
    ) -> Result<Schedule, ScheduleError> {
        authorize(role, &new)?;
        let id = random_id().ok_or(ScheduleError::IdUnavailable)?;
        let created = self
            .state
            .update_if_changed(|doc: &mut SchedulesDocument| {
                let admitted = admit(doc, &new, None).and_then(|()| {
                    doc.schedules
                        .iter()
                        .all(|schedule| schedule.id != id)
                        .then_some(())
                        .ok_or(ScheduleError::IdUnavailable)
                });
                if let Err(error) = admitted {
                    return persist::Edit::Unchanged(Err(error));
                }
                let schedule = Schedule {
                    id: id.clone(),
                    name: new.name,
                    router: new.router,
                    when: new.when,
                    action: new.action,
                    owner,
                    state: ScheduleState::Active,
                    created_at: now,
                    updated_at: now,
                };
                doc.schedules.push(schedule.clone());
                persist::Edit::Changed(Ok(schedule))
            })??;
        self.ledger.fire_until(&created.id, now)?;
        Ok(created)
    }

    /// Replaces every user-set field of schedule `id` and makes `owner` its owner.
    ///
    /// # Errors
    ///
    /// As [`Self::create`] for the edited schedule; the role must also hold the current
    /// action's permissions on the current router, and [`ScheduleError::NotFound`].
    #[inline]
    pub fn update(
        &self,
        role: &Role,
        id: &str,
        edit: Edit,
        owner: Owner,
        now: i64,
    ) -> Result<Schedule, ScheduleError> {
        authorize(role, &edit)?;
        let updated = self.modify(role, id, |doc, index| {
            admit(doc, &edit, Some(id))?;
            let schedule = doc
                .schedules
                .get_mut(index)
                .ok_or(ScheduleError::NotFound)?;
            schedule.name = edit.name;
            schedule.router = edit.router;
            schedule.when = edit.when;
            schedule.action = edit.action;
            schedule.owner = owner;
            schedule.updated_at = now;
            Ok(schedule.clone())
        })?;
        self.ledger.fire_until(id, now)?;
        Ok(updated)
    }

    /// Pauses schedule `id` by hand; its owner stays.
    ///
    /// # Errors
    ///
    /// [`ScheduleError::Forbidden`], [`ScheduleError::NotFound`] or
    /// [`ScheduleError::State`].
    #[inline]
    pub fn pause(&self, role: &Role, id: &str, now: i64) -> Result<Schedule, ScheduleError> {
        self.modify(role, id, |doc, index| {
            let schedule = doc
                .schedules
                .get_mut(index)
                .ok_or(ScheduleError::NotFound)?;
            schedule.state = ScheduleState::Paused {
                reason: PauseReason::Manual,
                at: now,
            };
            Ok(schedule.clone())
        })
    }

    /// Resumes schedule `id` with `owner` as its owner; slots up to `now` never fire.
    ///
    /// A preset's source router is not checked here (the store does not open presets);
    /// every run checks it again.
    ///
    /// # Errors
    ///
    /// [`ScheduleError::Forbidden`], [`ScheduleError::NotFound`] or
    /// [`ScheduleError::State`].
    #[inline]
    pub fn resume(
        &self,
        role: &Role,
        id: &str,
        owner: Owner,
        now: i64,
    ) -> Result<Schedule, ScheduleError> {
        let resumed = self.modify(role, id, |doc, index| {
            let schedule = doc
                .schedules
                .get_mut(index)
                .ok_or(ScheduleError::NotFound)?;
            schedule.state = ScheduleState::Active;
            schedule.owner = owner;
            schedule.updated_at = now;
            Ok(schedule.clone())
        })?;
        self.ledger.fire_until(id, now)?;
        Ok(resumed)
    }

    /// Deletes schedule `id` and its run history.
    ///
    /// # Errors
    ///
    /// [`ScheduleError::Forbidden`], [`ScheduleError::NotFound`] or
    /// [`ScheduleError::State`].
    #[inline]
    pub fn delete(&self, role: &Role, id: &str) -> Result<(), ScheduleError> {
        drop(self.modify(role, id, |doc, index| Ok(doc.schedules.remove(index)))?);
        self.ledger.forget(id).map_err(|error| match error {
            RunError::State(state) => ScheduleError::State(state),
            RunError::AlreadyFired | RunError::NotFound => ScheduleError::NotFound,
        })
    }

    /// Pauses schedule `id` for `reason` (a system path: a run found its owner or router
    /// unusable). A paused schedule keeps its earlier pause.
    ///
    /// # Errors
    ///
    /// [`ScheduleError::NotFound`] or [`ScheduleError::State`].
    #[inline]
    pub fn pause_for(
        &self,
        id: &str,
        reason: PauseReason,
        now: i64,
    ) -> Result<Schedule, ScheduleError> {
        self.state
            .update_if_changed(|doc: &mut SchedulesDocument| {
                let Some(schedule) = doc.schedules.iter_mut().find(|schedule| schedule.id == id)
                else {
                    return persist::Edit::Unchanged(Err(ScheduleError::NotFound));
                };
                if schedule.state == ScheduleState::Active {
                    schedule.state = ScheduleState::Paused { reason, at: now };
                    persist::Edit::Changed(Ok(schedule.clone()))
                } else {
                    persist::Edit::Unchanged(Ok(schedule.clone()))
                }
            })?
    }

    /// Pauses every active schedule of removed router `router` and returns their ids.
    ///
    /// # Errors
    ///
    /// [`ScheduleError::State`].
    #[inline]
    pub fn pause_router(&self, router: &str, now: i64) -> Result<Vec<String>, ScheduleError> {
        Ok(self
            .state
            .update_if_changed(|doc: &mut SchedulesDocument| {
                let mut paused = Vec::new();
                for schedule in &mut doc.schedules {
                    if schedule.router == router && schedule.state == ScheduleState::Active {
                        schedule.state = ScheduleState::Paused {
                            reason: PauseReason::RouterRemoved,
                            at: now,
                        };
                        paused.push(schedule.id.clone());
                    }
                }
                if paused.is_empty() {
                    persist::Edit::Unchanged(paused)
                } else {
                    persist::Edit::Changed(paused)
                }
            })?)
    }

    /// Runs `change` on schedule `id` under the document lock, after checking that the
    /// role may manage it, and writes the document when `change` succeeds.
    ///
    /// # Errors
    ///
    /// [`ScheduleError::NotFound`] (also outside the scope), [`ScheduleError::Forbidden`],
    /// what `change` returns, or [`ScheduleError::State`].
    fn modify<F, R>(&self, role: &Role, id: &str, change: F) -> Result<R, ScheduleError>
    where
        F: FnOnce(&mut SchedulesDocument, usize) -> Result<R, ScheduleError>,
    {
        require_manage(role)?;
        self.state
            .update_if_changed(|doc: &mut SchedulesDocument| {
                let found = doc
                    .schedules
                    .iter()
                    .position(|schedule| schedule.id == id && visible(role, schedule))
                    .ok_or(ScheduleError::NotFound);
                let checked = found.and_then(|index| {
                    let schedule = doc.schedules.get(index).ok_or(ScheduleError::NotFound)?;
                    access::authorize_existing(role, schedule).map(|()| index)
                });
                match checked.and_then(|index| change(doc, index)) {
                    Ok(result) => persist::Edit::Changed(Ok(result)),
                    Err(error) => persist::Edit::Unchanged(Err(error)),
                }
            })?
    }
}
