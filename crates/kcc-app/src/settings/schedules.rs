//! `[schedules]` section: defaults for scheduled actions.

use serde::Deserialize;

use super::{ConfigError, invalid};
use crate::schedules::time::ZoneName;

/// `[schedules]` section.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
#[non_exhaustive]
#[expect(
    clippy::module_name_repetitions,
    reason = "the config root names every section type `<Section>Config`"
)]
pub struct SchedulesConfig {
    /// IANA zone that prefills schedule forms and dates messages about anything else.
    pub default_timezone: String,
}

impl Default for SchedulesConfig {
    #[inline]
    fn default() -> Self {
        Self {
            default_timezone: "UTC".to_owned(),
        }
    }
}

impl SchedulesConfig {
    /// The zone is in the bundled time zone database.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Invalid`] naming `schedules.default_timezone`.
    pub(super) fn validate(&self) -> Result<(), ConfigError> {
        ZoneName::parse(&self.default_timezone)
            .map(drop)
            .map_err(|_unknown| {
                invalid(
                    "schedules.default_timezone",
                    "must be an IANA time zone name such as Europe/Berlin",
                )
            })
    }
}
