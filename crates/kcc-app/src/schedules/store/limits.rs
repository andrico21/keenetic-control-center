//! How many schedules may exist, and under which names.

use super::{MAX_PER_ROUTER, MAX_TOTAL, ScheduleError, SchedulesDocument};
use crate::schedules::model::NewSchedule;

/// Checks the name and the limits for `new` in `doc`, ignoring schedule `editing`.
///
/// # Errors
///
/// [`ScheduleError::DuplicateName`], [`ScheduleError::RouterLimit`] or
/// [`ScheduleError::TotalLimit`].
pub(super) fn admit(
    doc: &SchedulesDocument,
    new: &NewSchedule,
    editing: Option<&str>,
) -> Result<(), ScheduleError> {
    let others = doc
        .schedules
        .iter()
        .filter(|schedule| Some(schedule.id.as_str()) != editing);
    let mut total = 0_usize;
    let mut on_router = 0_usize;
    for schedule in others {
        total = total.saturating_add(1);
        if schedule.router == new.router {
            on_router = on_router.saturating_add(1);
            if schedule.name == new.name {
                return Err(ScheduleError::DuplicateName);
            }
        }
    }
    if on_router >= MAX_PER_ROUTER {
        return Err(ScheduleError::RouterLimit);
    }
    if total >= MAX_TOTAL {
        return Err(ScheduleError::TotalLimit);
    }
    Ok(())
}
