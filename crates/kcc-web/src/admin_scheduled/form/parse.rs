//! The dialog's fields checked into a schedule, or the messages under the refused ones.

use kcc_app::schedules::{
    model::{
        Action, NewSchedule,
        names::{ClientMac, PolicyName, PresetId, ScheduleName},
    },
    time::{DaySet, TimeError, WeeklyTime, ZoneName},
};
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};

use super::{Errors, Field, Typed};

/// A refused field and the message under it.
type Refusal = (Field, MessageKey);

/// The schedule the fields of `typed` describe, on one of `routers`, or the messages in
/// `locale` under every refused field.
///
/// # Errors
///
/// The field errors when any field is refused.
pub(in crate::admin_scheduled) fn schedule(
    typed: &Typed,
    routers: &[String],
    locale: Locale,
) -> Result<NewSchedule, Box<Errors>> {
    let named = ScheduleName::parse(typed.name.trim())
        .map_err(|_refused| (Field::Name, keys::WEB_ADMIN_SCHEDULED_ERROR_NAME));
    let chosen = routers
        .iter()
        .find(|known| **known == typed.router)
        .cloned()
        .ok_or((Field::Router, keys::WEB_ADMIN_SCHEDULED_ERROR_ROUTER));
    let timed = when(typed);
    let acted = action(typed);
    let (Ok(name), Ok(router), Ok(when), Ok(action)) = (&named, &chosen, &timed, &acted) else {
        let mut errors = Errors::default();
        let refusals = [named.err(), chosen.err(), timed.err(), acted.err()];
        for (field, key) in refusals.into_iter().flatten() {
            errors.set(field, tr(locale, key, None));
        }
        return Err(Box::new(errors));
    };
    if *action == Action::Reboot && typed.confirm_name.trim() != router.as_str() {
        let mut errors = Errors::default();
        errors.set(
            Field::Confirm,
            tr(locale, keys::WEB_ADMIN_SCHEDULED_ERROR_CONFIRM, None),
        );
        return Err(Box::new(errors));
    }
    Ok(NewSchedule::new(
        name.clone(),
        router.clone(),
        when.clone(),
        action.clone(),
    ))
}

/// The weekly time of the days, hour, minute and zone fields of `typed`.
///
/// # Errors
///
/// The first refused field, in the order days, hour, minute, zone.
fn when(typed: &Typed) -> Result<WeeklyTime, Refusal> {
    let days = DaySet::from_names(&typed.days)
        .map_err(|_refused| (Field::Days, keys::WEB_SYSTEM_SCHEDULES_DAYS_ERROR))?;
    let hour = typed
        .hour
        .trim()
        .parse::<u8>()
        .ok()
        .filter(|hour| *hour <= 23)
        .ok_or((Field::Hour, keys::WEB_ADMIN_SCHEDULED_ERROR_HOUR))?;
    let minute = typed
        .minute
        .trim()
        .parse::<u8>()
        .ok()
        .filter(|minute| *minute <= 59)
        .ok_or((Field::Minute, keys::WEB_ADMIN_SCHEDULED_ERROR_MINUTE))?;
    let zone_refused = (Field::Zone, keys::WEB_ADMIN_SCHEDULED_ERROR_ZONE);
    let zone = ZoneName::parse(typed.zone.trim()).map_err(|_refused| zone_refused)?;
    WeeklyTime::new(days, hour, minute, zone).map_err(|refused: TimeError| {
        if matches!(refused, TimeError::Days) {
            (Field::Days, keys::WEB_SYSTEM_SCHEDULES_DAYS_ERROR)
        } else if matches!(refused, TimeError::Hour) {
            (Field::Hour, keys::WEB_ADMIN_SCHEDULED_ERROR_HOUR)
        } else if matches!(refused, TimeError::Minute) {
            (Field::Minute, keys::WEB_ADMIN_SCHEDULED_ERROR_MINUTE)
        } else {
            zone_refused
        }
    })
}

/// The action of the action fields of `typed`.
///
/// # Errors
///
/// The refused field.
fn action(typed: &Typed) -> Result<Action, Refusal> {
    match typed.kind.as_str() {
        "policy_switch" => Ok(Action::PolicySwitch {
            mac: ClientMac::parse(&typed.mac)
                .map_err(|_refused| (Field::Client, keys::WEB_ADMIN_SCHEDULED_ERROR_CLIENT))?,
            policy: PolicyName::parse(&typed.policy)
                .map_err(|_refused| (Field::Policy, keys::WEB_ADMIN_SCHEDULED_ERROR_POLICY))?,
        }),
        "preset" => Ok(Action::Preset {
            preset_id: PresetId::parse(&typed.preset)
                .map_err(|_refused| (Field::Preset, keys::WEB_ADMIN_SCHEDULED_ERROR_PRESET))?,
            ack_documentation_tier: typed.ack,
        }),
        "backup" => Ok(Action::Backup),
        "reboot" => Ok(Action::Reboot),
        _ => Err((Field::Kind, keys::WEB_ADMIN_SCHEDULED_ERROR_ACTION)),
    }
}
