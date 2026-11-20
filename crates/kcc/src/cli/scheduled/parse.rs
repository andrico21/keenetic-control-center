//! The command line's schedule fields, each parsed once; a refusal names only the flag.

use kcc_app::schedules::{
    model::{
        Action,
        names::{ClientMac, PolicyName, PresetId, ScheduleName},
    },
    time::{DaySet, WeeklyTime, ZoneName},
};
use kcc_i18n::keys;

use crate::cli::{
    args_scheduled::{ScheduledActionArgs, ScheduledPresetArgs, ScheduledSwitchArgs},
    exit::{Exit, Failure},
};

/// A schedule field the command line got wrong.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Field {
    /// `--name`.
    Name,
    /// `--days`.
    Days,
    /// `--at`.
    At,
    /// `--tz`, or `[schedules] default_timezone`.
    Zone,
    /// `--mac`.
    Mac,
    /// `--policy`.
    Policy,
    /// `--preset`.
    Preset,
    /// The action flags, none of which was given.
    Action,
}

impl Field {
    /// The flag that carries the field.
    const fn flag(self) -> &'static str {
        match self {
            Self::Name => "--name",
            Self::Days => "--days",
            Self::At => "--at",
            Self::Zone => "--tz",
            Self::Mac => "--mac",
            Self::Policy => "--policy",
            Self::Preset => "--preset",
            Self::Action => "--policy-switch|--preset|--backup|--reboot",
        }
    }
}

impl From<Field> for Failure {
    fn from(field: Field) -> Self {
        Self::message(
            Exit::Usage,
            keys::CLI_SCHEDULED_INVALID,
            &[("field", field.flag())],
        )
    }
}

/// A name of 1 to 64 characters without a control character.
///
/// # Errors
///
/// [`Field::Name`].
pub(super) fn name(text: &str) -> Result<ScheduleName, Field> {
    ScheduleName::parse(text).map_err(|_error| Field::Name)
}

/// Comma-separated weekday names, `mon` to `sun`, in any case; at least one.
///
/// # Errors
///
/// [`Field::Days`].
pub(super) fn days(text: &str) -> Result<DaySet, Field> {
    DaySet::from_names(text.split(',').map(|day| day.trim().to_ascii_lowercase()))
        .map_err(|_error| Field::Days)
}

/// `HH:MM` (or `H:MM`), 00:00 to 23:59.
///
/// # Errors
///
/// [`Field::At`].
pub(super) fn at(text: &str) -> Result<(u8, u8), Field> {
    let (hours, minutes) = text.split_once(':').ok_or(Field::At)?;
    let digits = |part: &str| part.bytes().all(|byte| byte.is_ascii_digit());
    let shaped = (1..=2).contains(&hours.len()) && minutes.len() == 2;
    if !shaped || !digits(hours) || !digits(minutes) {
        return Err(Field::At);
    }
    let hour = hours.parse::<u8>().map_err(|_error| Field::At)?;
    let minute = minutes.parse::<u8>().map_err(|_error| Field::At)?;
    (hour <= 23 && minute <= 59)
        .then_some((hour, minute))
        .ok_or(Field::At)
}

/// An IANA zone of the bundled database, in any case.
///
/// # Errors
///
/// [`Field::Zone`].
pub(super) fn zone(text: &str) -> Result<ZoneName, Field> {
    ZoneName::parse(text).map_err(|_error| Field::Zone)
}

/// The weekly slot of `days` at `hour:minute` in `zone`.
///
/// # Errors
///
/// [`Field::At`] for a time outside the day.
pub(super) fn when(
    days: DaySet,
    (hour, minute): (u8, u8),
    zone: ZoneName,
) -> Result<WeeklyTime, Field> {
    WeeklyTime::new(days, hour, minute, zone).map_err(|_error| Field::At)
}

/// The action the flags choose, or `None` when they choose none.
///
/// # Errors
///
/// The field of an invalid MAC address, policy name or preset id.
pub(super) fn action(args: ScheduledActionArgs) -> Result<Option<Action>, Field> {
    let ScheduledActionArgs {
        switch:
            ScheduledSwitchArgs {
                policy_switch,
                mac: client,
                policy: name,
            },
        preset:
            ScheduledPresetArgs {
                preset,
                ack_documentation_tier,
            },
        backup,
        reboot,
    } = args;
    if policy_switch {
        let mac =
            ClientMac::parse(client.as_deref().unwrap_or_default()).map_err(|_error| Field::Mac)?;
        let policy = PolicyName::parse(name.as_deref().unwrap_or_default())
            .map_err(|_error| Field::Policy)?;
        return Ok(Some(Action::PolicySwitch { mac, policy }));
    }
    if let Some(id) = preset {
        let preset_id = PresetId::parse(&id).map_err(|_error| Field::Preset)?;
        return Ok(Some(Action::Preset {
            preset_id,
            ack_documentation_tier,
        }));
    }
    Ok(if backup {
        Some(Action::Backup)
    } else if reboot {
        Some(Action::Reboot)
    } else {
        None
    })
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use kcc_app::schedules::model::Action;

    use super::{Field, action, at, days, zone};
    use crate::cli::args_scheduled::{
        ScheduledActionArgs, ScheduledPresetArgs, ScheduledSwitchArgs,
    };

    /// No action flag.
    const fn none() -> ScheduledActionArgs {
        ScheduledActionArgs {
            switch: ScheduledSwitchArgs {
                policy_switch: false,
                mac: None,
                policy: None,
            },
            preset: ScheduledPresetArgs {
                preset: None,
                ack_documentation_tier: false,
            },
            backup: false,
            reboot: false,
        }
    }

    /// Todo 16: times run from 00:00 to 23:59; anything else names `--at`.
    #[test]
    fn times_are_hours_and_minutes_of_one_day() {
        assert_eq!(at("00:00"), Ok((0, 0)));
        assert_eq!(at("3:05"), Ok((3, 5)));
        assert_eq!(at("23:59"), Ok((23, 59)));
        for wrong in [
            "24:00", "12:60", "12", "12:5", "123:00", "-1:00", "1a:00", "", ":",
        ] {
            assert_eq!(at(wrong), Err(Field::At), "{wrong:?}");
        }
    }

    /// Todo 16: days are a non-empty comma-separated list of known names.
    #[test]
    fn days_need_at_least_one_known_name() {
        let parsed = days("Mon, wed,mon").map(|set| set.names().collect::<Vec<_>>());
        assert_eq!(parsed, Ok(vec!["mon", "wed"]));
        for wrong in ["", "mon,", "monday", "mon;tue"] {
            assert_eq!(days(wrong).err(), Some(Field::Days), "{wrong:?}");
        }
    }

    /// Todo 16: a zone of the bundled database is kept in its canonical spelling.
    #[test]
    fn zones_come_from_the_bundled_database() {
        assert_eq!(
            zone("europe/berlin").map(|name| name.as_str().to_owned()),
            Ok("Europe/Berlin".to_owned())
        );
        assert_eq!(zone("Mars/Base").err(), Some(Field::Zone));
    }

    /// Todo 16: a policy switch needs a valid MAC and policy name; no flag is no action.
    #[test]
    fn actions_name_the_wrong_flag() {
        let switch = |mac: &str, policy: &str| ScheduledActionArgs {
            switch: ScheduledSwitchArgs {
                policy_switch: true,
                mac: Some(mac.to_owned()),
                policy: Some(policy.to_owned()),
            },
            ..none()
        };
        assert!(matches!(
            action(switch("02-00-00-00-16-0A", "Policy0")),
            Ok(Some(Action::PolicySwitch { mac, policy: _ })) if mac.as_str() == "02:00:00:00:16:0a"
        ));
        assert_eq!(
            action(switch("02:00:00:00:16", "Policy0")).err(),
            Some(Field::Mac)
        );
        assert_eq!(
            action(switch("02:00:00:00:16:01", "two words")).err(),
            Some(Field::Policy)
        );
        assert_eq!(action(none()), Ok(None));
        let reboot = ScheduledActionArgs {
            reboot: true,
            ..none()
        };
        assert_eq!(action(reboot), Ok(Some(Action::Reboot)));
    }
}
