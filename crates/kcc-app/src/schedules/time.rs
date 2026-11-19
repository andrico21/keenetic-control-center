//! Weekly slot times on the IANA time zone database bundled into the binary.
//!
//! The system time zone and zoneinfo files are never read: every zone comes from
//! [`zones`], so a slot falls at the same instant on every host.

use std::sync::OnceLock;

use jiff::{
    Timestamp,
    civil::Weekday,
    fmt::strtime,
    tz::{TimeZone, TimeZoneDatabase},
};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

/// Weekday names in serde order, Monday first, with their bit in a [`DaySet`].
const DAYS: [(&str, Weekday, u8); 7] = [
    ("mon", Weekday::Monday, 0b000_0001),
    ("tue", Weekday::Tuesday, 0b000_0010),
    ("wed", Weekday::Wednesday, 0b000_0100),
    ("thu", Weekday::Thursday, 0b000_1000),
    ("fri", Weekday::Friday, 0b001_0000),
    ("sat", Weekday::Saturday, 0b010_0000),
    ("sun", Weekday::Sunday, 0b100_0000),
];

/// Civil dates searched for the next slot: the local date of `after` and the eight after it.
const SEARCH_DAYS: usize = 9;

/// The bundled IANA time zone database, the only one kcc reads.
#[must_use]
#[inline]
pub fn zones() -> &'static TimeZoneDatabase {
    /// Built on first use; the bundled data needs no file or environment access.
    static ZONES: OnceLock<TimeZoneDatabase> = OnceLock::new();
    ZONES.get_or_init(TimeZoneDatabase::bundled)
}

/// A rejected weekly time; names only the field, never the rejected value.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
#[expect(
    clippy::module_name_repetitions,
    reason = "the schedule model and front ends import this type unqualified next to other errors"
)]
pub enum TimeError {
    /// The zone is not in the bundled database.
    #[error("invalid zone")]
    Zone,
    /// The day list is empty or names an unknown day.
    #[error("invalid days")]
    Days,
    /// The hour is outside 0..=23.
    #[error("invalid hour")]
    Hour,
    /// The minute is outside 0..=59.
    #[error("invalid minute")]
    Minute,
}

/// A canonical IANA zone name present in the bundled database.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[non_exhaustive]
pub struct ZoneName(String);

impl ZoneName {
    /// Looks `name` up in [`zones`] without regard to ASCII case and keeps its canonical
    /// spelling (`europe/berlin` becomes `Europe/Berlin`).
    ///
    /// # Errors
    ///
    /// [`TimeError::Zone`] when the bundled database has no such zone.
    #[inline]
    pub fn parse(name: &str) -> Result<Self, TimeError> {
        zones()
            .get(name)
            .ok()
            .and_then(|zone| zone.iana_name().map(str::to_owned))
            .map(Self)
            .ok_or(TimeError::Zone)
    }

    /// The canonical name.
    #[must_use]
    #[inline]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The zone's rules; a parsed name is always present in [`zones`].
    fn time_zone(&self) -> TimeZone {
        zones().get(&self.0).unwrap_or(TimeZone::UTC)
    }
}

impl Serialize for ZoneName {
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ZoneName {
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let name = String::deserialize(deserializer)?;
        Self::parse(&name).map_err(D::Error::custom)
    }
}

/// A non-empty set of weekdays, serialized as a list of `"mon"`..`"sun"`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub struct DaySet(u8);

impl DaySet {
    /// Builds the set from day names `"mon"`..`"sun"`; repeated names count once.
    ///
    /// # Errors
    ///
    /// [`TimeError::Days`] when `names` is empty or holds an unknown name.
    #[inline]
    pub fn from_names<I>(names: I) -> Result<Self, TimeError>
    where
        I: IntoIterator,
        I::Item: AsRef<str>,
    {
        let mut bits = 0_u8;
        for name in names {
            let (_name, _day, bit) = DAYS
                .iter()
                .find(|(known, _day, _bit)| *known == name.as_ref())
                .ok_or(TimeError::Days)?;
            bits |= bit;
        }
        (bits != 0).ok_or(TimeError::Days).map(|()| Self(bits))
    }

    /// Whether `day` is in the set.
    #[must_use]
    #[inline]
    pub fn contains(self, day: Weekday) -> bool {
        DAYS.iter()
            .any(|(_name, known, bit)| *known == day && self.0 & bit != 0)
    }

    /// The day names in the set, Monday first.
    #[inline]
    pub fn names(self) -> impl Iterator<Item = &'static str> {
        DAYS.iter()
            .filter(move |(_name, _day, bit)| self.0 & bit != 0)
            .map(|(name, _day, _bit)| *name)
    }
}

impl Serialize for DaySet {
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_seq(self.names())
    }
}

impl<'de> Deserialize<'de> for DaySet {
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let names = Vec::<String>::deserialize(deserializer)?;
        Self::from_names(names).map_err(D::Error::custom)
    }
}

/// A time of day on some weekdays in one zone.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[non_exhaustive]
#[expect(
    clippy::module_name_repetitions,
    reason = "the schedule model stores this type unqualified as a schedule's `when`"
)]
pub struct WeeklyTime {
    /// The weekdays the slot falls on.
    days: DaySet,
    /// Local hour, 0..=23.
    hour: u8,
    /// Local minute, 0..=59.
    minute: u8,
    /// The zone whose civil time `hour:minute` is.
    zone: ZoneName,
}

impl WeeklyTime {
    /// A slot at `hour:minute` local time in `zone` on every day of `days`.
    ///
    /// # Errors
    ///
    /// [`TimeError::Hour`] for an hour above 23, [`TimeError::Minute`] for a minute
    /// above 59.
    #[inline]
    pub fn new(days: DaySet, hour: u8, minute: u8, zone: ZoneName) -> Result<Self, TimeError> {
        (hour <= 23).ok_or(TimeError::Hour)?;
        (minute <= 59).ok_or(TimeError::Minute)?;
        Ok(Self {
            days,
            hour,
            minute,
            zone,
        })
    }

    /// The weekdays.
    #[must_use]
    #[inline]
    pub const fn days(&self) -> DaySet {
        self.days
    }

    /// The local hour.
    #[must_use]
    #[inline]
    pub const fn hour(&self) -> u8 {
        self.hour
    }

    /// The local minute.
    #[must_use]
    #[inline]
    pub const fn minute(&self) -> u8 {
        self.minute
    }

    /// The zone.
    #[must_use]
    #[inline]
    pub const fn zone(&self) -> &ZoneName {
        &self.zone
    }

    /// The earliest slot strictly after `after`.
    ///
    /// Each civil date from `after`'s local date on is tried in turn; a local time that
    /// falls into a gap moves forward by the gap, one that occurs twice takes the earlier
    /// instant, so a slot never runs twice on one date. `None` only at the end of jiff's
    /// time range.
    #[must_use]
    #[inline]
    pub fn next_slot(&self, after: Timestamp) -> Option<Timestamp> {
        let zone = self.zone.time_zone();
        let hour = i8::try_from(self.hour).ok()?;
        let minute = i8::try_from(self.minute).ok()?;
        let mut date = zone.to_datetime(after).date();
        for _day in 0..SEARCH_DAYS {
            if self.days.contains(date.weekday()) {
                let slot = zone
                    .to_ambiguous_timestamp(date.at(hour, minute, 0, 0))
                    .compatible()
                    .ok()?;
                if slot > after {
                    return Some(slot);
                }
            }
            date = date.tomorrow().ok()?;
        }
        None
    }

    /// [`Self::next_slot`] in Unix seconds, for crates without a jiff dependency.
    #[must_use]
    #[inline]
    pub fn next_slot_unix(&self, after: i64) -> Option<i64> {
        Timestamp::from_second(after)
            .ok()
            .and_then(|instant| self.next_slot(instant))
            .map(Timestamp::as_second)
    }
}

impl<'de> Deserialize<'de> for WeeklyTime {
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        /// The stored fields before their ranges are checked.
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Fields {
            /// See [`WeeklyTime::days`].
            days: DaySet,
            /// See [`WeeklyTime::hour`].
            hour: u8,
            /// See [`WeeklyTime::minute`].
            minute: u8,
            /// See [`WeeklyTime::zone`].
            zone: ZoneName,
        }
        let Fields {
            days,
            hour,
            minute,
            zone,
        } = Fields::deserialize(deserializer)?;
        Self::new(days, hour, minute, zone).map_err(D::Error::custom)
    }
}

/// `unix` as local time in `zone`, `YYYY-MM-DD HH:MM +HH:MM`, for messages and pages.
#[must_use]
#[inline]
pub fn format_local(unix: i64, zone: &ZoneName) -> String {
    let instant = Timestamp::from_second(unix).unwrap_or(if unix < 0 {
        Timestamp::MIN
    } else {
        Timestamp::MAX
    });
    let local = instant.to_zoned_datetime(zone.time_zone());
    strtime::format("%Y-%m-%d %H:%M %:z", &local).unwrap_or_else(|_error| instant.to_string())
}

#[cfg(test)]
mod tests;
