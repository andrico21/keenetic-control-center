//! Slot arithmetic, zone names and refusals of the weekly slot model.
#![expect(
    clippy::panic_in_result_fn,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test assertions deliberately panic and are not rendered API documentation"
)]

use core::error::Error;

use jiff::Timestamp;

use super::{DaySet, TimeError, WeeklyTime, ZoneName, format_local, zones};

/// Result of a test that propagates setup errors.
type TestResult = Result<(), Box<dyn Error>>;

/// A weekly time from day names, hour, minute and a zone name.
fn weekly(days: &[&str], hour: u8, minute: u8, zone: &str) -> Result<WeeklyTime, TimeError> {
    WeeklyTime::new(
        DaySet::from_names(days)?,
        hour,
        minute,
        ZoneName::parse(zone)?,
    )
}

/// The next slot after the RFC 3339 instant `after`, as RFC 3339.
fn slot_after(when: &WeeklyTime, after: &str) -> Result<Option<String>, Box<dyn Error>> {
    Ok(when.next_slot(after.parse()?).map(|slot| slot.to_string()))
}

/// todo 2: the binary carries a non-empty zone database.
#[test]
fn bundled_database_is_not_empty() {
    assert!(zones().available().next().is_some(), "no bundled zone");
}

/// todo 2: a Sunday 02:30 Berlin slot inside the spring-forward gap runs at 03:30 CEST.
#[test]
fn gap_slot_moves_forward() -> TestResult {
    let when = weekly(&["sun"], 2, 30, "Europe/Berlin")?;
    assert_eq!(
        slot_after(&when, "2027-03-27T12:00:00Z")?.as_deref(),
        Some("2027-03-28T01:30:00Z"),
        "gap slot"
    );
    Ok(())
}

/// todo 2: a Sunday 02:30 Berlin slot inside the fall-back fold runs once, at the
/// earlier instant, and next a week later.
#[test]
fn fold_slot_runs_once_at_the_earlier_instant() -> TestResult {
    let when = weekly(&["sun"], 2, 30, "Europe/Berlin")?;
    assert_eq!(
        slot_after(&when, "2027-10-30T12:00:00Z")?.as_deref(),
        Some("2027-10-31T00:30:00Z"),
        "first fold slot"
    );
    assert_eq!(
        slot_after(&when, "2027-10-31T00:30:00Z")?.as_deref(),
        Some("2027-11-07T01:30:00Z"),
        "slot after the fold"
    );
    Ok(())
}

/// todo 2: Almaty is UTC+5 since 2024, which only a recent bundled database knows.
#[test]
fn almaty_uses_its_current_offset() -> TestResult {
    let when = weekly(&["mon"], 8, 0, "Asia/Almaty")?;
    assert_eq!(
        slot_after(&when, "2027-01-01T00:00:00Z")?.as_deref(),
        Some("2027-01-04T03:00:00Z"),
        "Almaty slot"
    );
    Ok(())
}

/// todo 2: zone names are matched without regard to case and stored canonically.
#[test]
fn zone_names_are_canonical() -> TestResult {
    assert_eq!(
        ZoneName::parse("europe/berlin")?.as_str(),
        "Europe/Berlin",
        "canonical"
    );
    Ok(())
}

/// todo 2: unknown zones, empty or unknown days and out-of-range times are refused.
#[test]
fn invalid_parts_are_refused() -> TestResult {
    let berlin = ZoneName::parse("Europe/Berlin")?;
    let monday = DaySet::from_names(["mon"])?;
    assert_eq!(ZoneName::parse("Mars/Base"), Err(TimeError::Zone), "zone");
    assert_eq!(DaySet::from_names([""; 0]), Err(TimeError::Days), "no days");
    assert_eq!(
        DaySet::from_names(["mon", "xyz"]),
        Err(TimeError::Days),
        "unknown day"
    );
    assert_eq!(
        WeeklyTime::new(monday, 24, 0, berlin.clone()),
        Err(TimeError::Hour),
        "hour"
    );
    assert_eq!(
        WeeklyTime::new(monday, 23, 60, berlin),
        Err(TimeError::Minute),
        "minute"
    );
    Ok(())
}

/// todo 2: stored weekly times round-trip; days serialize Monday first.
#[test]
fn weekly_time_serde_round_trips() -> TestResult {
    let when = weekly(&["sun", "mon"], 7, 5, "utc")?;
    let json = serde_json::to_value(&when)?;
    assert_eq!(
        json,
        serde_json::json!({"days": ["mon", "sun"], "hour": 7_u8, "minute": 5_u8, "zone": "UTC"}),
        "stored form"
    );
    assert_eq!(
        serde_json::from_value::<WeeklyTime>(json)?,
        when,
        "round trip"
    );
    let empty = serde_json::json!({"days": [], "hour": 7_u8, "minute": 5_u8, "zone": "UTC"});
    assert!(
        serde_json::from_value::<WeeklyTime>(empty).is_err(),
        "empty days"
    );
    Ok(())
}

/// todo 2: local times carry the zone's offset at that instant.
#[test]
fn local_times_show_the_offset() -> TestResult {
    let slot: Timestamp = "2027-03-28T01:30:00Z".parse()?;
    let berlin = ZoneName::parse("Europe/Berlin")?;
    let new_york = ZoneName::parse("America/New_York")?;
    assert_eq!(
        format_local(slot.as_second(), &berlin),
        "2027-03-28 03:30 +02:00",
        "east"
    );
    assert_eq!(
        format_local(slot.as_second(), &new_york),
        "2027-03-27 21:30 -04:00",
        "west"
    );
    Ok(())
}
