//! Weekly slot properties over every zone of the bundled time zone database.

#[cfg(test)]
#[expect(
    clippy::panic_in_result_fn,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test assertions deliberately panic and are not rendered API documentation"
)]
mod tests {
    use core::{error::Error, ops::Range};

    use jiff::{SignedDuration, Timestamp, tz::AmbiguousOffset};
    use kcc_app::schedules::time::{DaySet, WeeklyTime, ZoneName, zones};
    use proptest::{
        prop_assert,
        sample::subsequence,
        test_runner::{Config, RngSeed, TestCaseError, TestRunner},
    };

    /// The day names a slot may list.
    const DAY_NAMES: [&str; 7] = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];

    /// 2026-01-01T00:00:00Z and 2041-01-01T00:00:00Z in Unix seconds.
    const AFTER_RANGE: Range<i64> = 1_767_225_600..2_240_611_200;

    /// Eight days and two hours: a week, plus room for a gap or an offset change.
    const LONGEST_WAIT: SignedDuration = SignedDuration::from_hours(194);

    /// Turns any error into a proptest failure.
    fn fail<E>(error: E) -> TestCaseError
    where
        E: Error,
    {
        TestCaseError::fail(error.to_string())
    }

    /// Checks the slot properties for one zone and one random weekly time.
    fn check(zone: &ZoneName, case: (Vec<&str>, u8, u8, i64)) -> Result<(), TestCaseError> {
        let (days, hour, minute, after_unix) = case;
        let set = DaySet::from_names(days).map_err(fail)?;
        let when = WeeklyTime::new(set, hour, minute, zone.clone()).map_err(fail)?;
        let after = Timestamp::from_second(after_unix).map_err(fail)?;
        let slot = when
            .next_slot(after)
            .ok_or_else(|| TestCaseError::fail("no slot"))?;
        prop_assert!(slot > after, "slot {slot} not after {after}");
        prop_assert!(
            slot.duration_since(after) <= LONGEST_WAIT,
            "slot {slot} too far after {after}"
        );
        let tz = zones().get(zone.as_str()).map_err(fail)?;
        let local = tz.to_datetime(slot);
        prop_assert!(
            set.contains(local.weekday()),
            "slot {local} on an unlisted day"
        );
        let (wanted_hour, wanted_minute) = (
            i8::try_from(hour).map_err(fail)?,
            i8::try_from(minute).map_err(fail)?,
        );
        if (local.hour(), local.minute()) != (wanted_hour, wanted_minute) {
            let civil = local.date().at(wanted_hour, wanted_minute, 0, 0);
            prop_assert!(
                matches!(
                    tz.to_ambiguous_timestamp(civil).offset(),
                    AmbiguousOffset::Gap {
                        before: _,
                        after: _
                    }
                ),
                "slot {local} off its time although {civil} exists"
            );
        }
        Ok(())
    }

    /// todo 2: in every bundled zone the next slot lies after `after`, at most eight days
    /// and two hours later, on a listed weekday, at the slot's local time unless that
    /// civil time does not exist that day.
    #[test]
    fn next_slot_holds_in_every_bundled_zone() -> Result<(), Box<dyn Error>> {
        let names: Vec<String> = zones()
            .available()
            .map(|name| name.as_str().to_owned())
            .collect();
        assert!(!names.is_empty(), "no bundled zone");
        for (seed, name) in (0_u64..).zip(&names) {
            let zone = ZoneName::parse(name)?;
            let config = Config {
                cases: 32,
                rng_seed: RngSeed::Fixed(seed),
                failure_persistence: None,
                ..Config::default()
            };
            let strategy = (
                subsequence(DAY_NAMES.to_vec(), 1..=7),
                0_u8..24,
                0_u8..60,
                AFTER_RANGE,
            );
            TestRunner::new(config)
                .run(&strategy, |case| check(&zone, case))
                .map_err(|error| format!("{name}: {error}"))?;
        }
        Ok(())
    }
}
