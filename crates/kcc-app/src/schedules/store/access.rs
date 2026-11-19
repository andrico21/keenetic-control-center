//! Who may manage which schedule.

use super::ScheduleError;
use crate::{
    permissions::{Permission, Role},
    registry::{self, scope_matches},
    schedules::model::{Action, NewSchedule, PRESET_SOURCE_PERMISSIONS, Schedule},
};

/// Requires `ManageSchedules`.
///
/// # Errors
///
/// [`ScheduleError::Forbidden`].
pub(super) fn require_manage(role: &Role) -> Result<(), ScheduleError> {
    role.grants(Permission::ManageSchedules)
        .then_some(())
        .ok_or(ScheduleError::Forbidden)
}

/// Whether `schedule`'s router is in the role's scope.
pub(super) fn visible(role: &Role, schedule: &Schedule) -> bool {
    scope_matches(&role.router_scope, &schedule.router)
}

/// Requires `ManageSchedules` and `action`'s permissions on `router`.
///
/// # Errors
///
/// [`ScheduleError::Forbidden`].
fn require_action(role: &Role, router: &str, action: &Action) -> Result<(), ScheduleError> {
    require_manage(role)?;
    require_all(role, action.permissions(), router)
}

/// Requires every one of `permissions` on `router`.
///
/// # Errors
///
/// [`ScheduleError::Forbidden`].
fn require_all(role: &Role, permissions: &[Permission], router: &str) -> Result<(), ScheduleError> {
    permissions.iter().try_for_each(|permission| {
        registry::authorize(role, *permission, router).map_err(|_denied| ScheduleError::Forbidden)
    })
}

/// Authorizes creating or editing to `new`, a preset's source router included.
///
/// # Errors
///
/// [`ScheduleError::Forbidden`].
pub(super) fn authorize(role: &Role, new: &NewSchedule) -> Result<(), ScheduleError> {
    require_action(role, &new.router, &new.action)?;
    match (&new.action, new.preset_source.as_deref()) {
        (
            Action::Preset {
                preset_id: _,
                ack_documentation_tier: _,
            },
            Some(source),
        ) => require_all(role, &PRESET_SOURCE_PERMISSIONS, source),
        (
            Action::Preset {
                preset_id: _,
                ack_documentation_tier: _,
            }
            | Action::PolicySwitch { mac: _, policy: _ }
            | Action::Backup
            | Action::Reboot,
            _,
        ) => Ok(()),
    }
}

/// Authorizes changing stored `schedule`: its action's permissions on its router.
///
/// # Errors
///
/// [`ScheduleError::Forbidden`].
pub(super) fn authorize_existing(role: &Role, schedule: &Schedule) -> Result<(), ScheduleError> {
    require_action(role, &schedule.router, &schedule.action)
}
