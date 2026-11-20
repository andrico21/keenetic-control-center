//! Which slot of a schedule is due, from the wall clock alone: pure arithmetic over
//! [`WeeklyTime::next_slot_unix`], no clock and no I/O.

use kcc_app::schedules::time::WeeklyTime;

/// Most slots looked at in one pass; a longer backlog is skipped over several passes.
const MAX_SLOTS: u32 = 10_000;

/// What a schedule's timetable says at one instant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Due {
    /// Nothing yet: the next slot, `None` when there is none.
    Wait(Option<i64>),
    /// This slot has come and is not too late.
    Run(i64),
    /// `count` slots, the last at `last`, are too late; `then` is a later slot that is
    /// not.
    Missed {
        /// How many.
        count: u32,
        /// The last too-late slot.
        last: i64,
        /// A slot after them that has come and is not too late.
        then: Option<i64>,
    },
}

/// The due state of `when` at `now` for the slots strictly after `after`; a slot more
/// than `late_limit` seconds before `now` is too late.
pub(super) fn due(when: &WeeklyTime, after: i64, now: i64, late_limit: i64) -> Due {
    let Some(first) = when.next_slot_unix(after) else {
        return Due::Wait(None);
    };
    if first > now {
        return Due::Wait(Some(first));
    }
    let mut count = 0_u32;
    let mut last = None;
    let mut slot = first;
    loop {
        if now.saturating_sub(slot) <= late_limit {
            return last.map_or(Due::Run(slot), |late| Due::Missed {
                count,
                last: late,
                then: Some(slot),
            });
        }
        count = count.saturating_add(1);
        last = Some(slot);
        match when.next_slot_unix(slot) {
            Some(next) if next <= now && count < MAX_SLOTS => slot = next,
            Some(_) | None => break,
        }
    }
    Due::Missed {
        count,
        last: slot,
        then: None,
    }
}

/// Whether a run of `slot` may still start at `now` on a busy router given `window`
/// seconds.
pub(super) const fn within_window(slot: i64, now: i64, window: i64) -> bool {
    now <= slot.saturating_add(window)
}

/// Seconds until `at`, from `now`, never negative.
pub(super) fn seconds_until(at: i64, now: i64) -> u64 {
    u64::try_from(at.saturating_sub(now)).unwrap_or(0)
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use core::error::Error;

    use kcc_app::schedules::time::{DaySet, WeeklyTime, ZoneName};

    use super::{Due, due, within_window};

    /// A day in seconds.
    const DAY: i64 = 86_400;

    /// 2027-01-04T03:00:00Z, a Monday.
    const SLOT: i64 = 1_799_031_600;

    /// Ten minutes before [`SLOT`]: the schedule's last change.
    const BEFORE: i64 = SLOT - 600;

    /// Every day at 03:00 UTC.
    fn daily() -> Result<WeeklyTime, Box<dyn Error>> {
        let days = DaySet::from_names(["mon", "tue", "wed", "thu", "fri", "sat", "sun"])?;
        Ok(WeeklyTime::new(days, 3, 0, ZoneName::parse("UTC")?)?)
    }

    /// Todo 13: a slot that has not come yet is waited for.
    #[test]
    fn a_future_slot_is_waited_for() -> Result<(), Box<dyn Error>> {
        const NOW: i64 = SLOT - 60;
        let when = daily()?;
        assert_eq!(due(&when, BEFORE, NOW, 120), Due::Wait(Some(SLOT)));
        Ok(())
    }

    /// Todo 13: a slot up to 120 s late runs; 121 s late is missed.
    #[test]
    fn the_two_minute_rule_is_inclusive() -> Result<(), Box<dyn Error>> {
        const IN_TIME: i64 = SLOT + 120;
        const LATE: i64 = SLOT + 121;
        let when = daily()?;
        assert_eq!(due(&when, BEFORE, IN_TIME, 120), Due::Run(SLOT));
        assert_eq!(
            due(&when, BEFORE, LATE, 120),
            Due::Missed {
                count: 1,
                last: SLOT,
                then: None
            }
        );
        Ok(())
    }

    /// Todo 13: three missed slots are one step naming 3, ending at the last of them.
    #[test]
    fn missed_slots_are_counted_once() -> Result<(), Box<dyn Error>> {
        const NOW: i64 = SLOT + 2 * DAY + 3_600;
        const THIRD: i64 = SLOT + 2 * DAY;
        let when = daily()?;
        assert_eq!(
            due(&when, BEFORE, NOW, 120),
            Due::Missed {
                count: 3,
                last: THIRD,
                then: None
            }
        );
        Ok(())
    }

    /// Todo 13: missed slots followed by one still in time: skip them, run that one.
    #[test]
    fn a_timely_slot_after_missed_ones_still_runs() -> Result<(), Box<dyn Error>> {
        const NOW: i64 = SLOT + DAY + 30;
        const NEXT: i64 = SLOT + DAY;
        let when = daily()?;
        assert_eq!(
            due(&when, BEFORE, NOW, 120),
            Due::Missed {
                count: 1,
                last: SLOT,
                then: Some(NEXT)
            }
        );
        Ok(())
    }

    /// Todo 13: the busy window ends exactly ten minutes after the slot.
    #[test]
    fn the_busy_window_is_inclusive() {
        const LAST: i64 = SLOT + 600;
        const AFTER: i64 = SLOT + 601;
        assert!(within_window(SLOT, LAST, 600));
        assert!(!within_window(SLOT, AFTER, 600));
    }
}
