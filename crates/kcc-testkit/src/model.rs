//! Router model profiles: hardware model plus firmware line.

use core::{error::Error, fmt, str::FromStr};

/// A simulated router hardware model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Model {
    /// Keenetic Ultra / Titan (`KN-1811`).
    Kn1811,
    /// Keenetic Giga (`KN-1010`).
    Kn1010,
    /// Keenetic Hopper (`KN-3810`).
    Kn3810,
    /// Netcraze Speedster (`NC-3013`).
    Nc3013,
}

impl Model {
    /// Every simulated model.
    pub const ALL: [Self; 4] = [Self::Kn1811, Self::Kn1010, Self::Kn3810, Self::Nc3013];

    /// The hardware id reported in `show version` (`hw_id`), e.g. `KN-1811`.
    #[inline]
    #[must_use]
    pub const fn hw_id(self) -> &'static str {
        match self {
            Self::Kn1811 => "KN-1811",
            Self::Kn1010 => "KN-1010",
            Self::Kn3810 => "KN-3810",
            Self::Nc3013 => "NC-3013",
        }
    }

    /// The ndw2 authentication realm the model advertises.
    #[inline]
    #[must_use]
    pub const fn realm(self) -> &'static str {
        match self {
            Self::Kn1811 => "Keenetic Ultra",
            Self::Kn1010 => "Keenetic Giga",
            Self::Kn3810 => "Keenetic Hopper",
            Self::Nc3013 => "Netcraze Speedster",
        }
    }

    /// The product name sent in `X-NDM-Product`.
    #[inline]
    #[must_use]
    pub const fn product(self) -> &'static str {
        match self {
            Self::Kn1811 => "Titan",
            Self::Kn1010 => "Giga",
            Self::Kn3810 => "Hopper",
            Self::Nc3013 => "Speedster",
        }
    }

    /// Firmware lines the fake router can simulate for this model.
    #[inline]
    #[must_use]
    pub const fn firmware_lines(self) -> &'static [Firmware] {
        match self {
            Self::Kn1811 => &[Firmware::V5_1, Firmware::V5_0, Firmware::V4_3],
            Self::Kn3810 => &[Firmware::V5_1, Firmware::V4_3],
            Self::Kn1010 | Self::Nc3013 => &[Firmware::V5_1],
        }
    }
}

impl fmt::Display for Model {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.hw_id())
    }
}

impl FromStr for Model {
    type Err = UnknownHardware;

    #[inline]
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|model| model.hw_id().eq_ignore_ascii_case(text))
            .ok_or(UnknownHardware)
    }
}

/// A simulated firmware line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Firmware {
    /// 4.3 LTS, documentation-derived.
    V4_3,
    /// 5.0, documentation-derived.
    V5_0,
    /// 5.1, seeded from the 5.1 fixtures.
    V5_1,
}

impl Firmware {
    /// The catalog line, e.g. `5.1`.
    #[inline]
    #[must_use]
    pub const fn line(self) -> &'static str {
        match self {
            Self::V4_3 => "4.3",
            Self::V5_0 => "5.0",
            Self::V5_1 => "5.1",
        }
    }

    /// The default `show version` `title`.
    #[inline]
    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            Self::V4_3 => "4.3.9",
            Self::V5_0 => "5.0.12",
            Self::V5_1 => "5.1.3",
        }
    }

    /// The default `show version` `release`.
    #[inline]
    #[must_use]
    pub const fn release(self) -> &'static str {
        match self {
            Self::V4_3 => "4.03.C.9.0-0",
            Self::V5_0 => "5.00.C.12.0-0",
            Self::V5_1 => "5.01.C.3.0-0",
        }
    }

    /// Whether the fixtures are derived from documentation rather than captures.
    #[inline]
    #[must_use]
    pub const fn documentation_derived(self) -> bool {
        match self {
            Self::V4_3 | Self::V5_0 => true,
            Self::V5_1 => false,
        }
    }
}

impl fmt::Display for Firmware {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.title())
    }
}

impl FromStr for Firmware {
    type Err = UnknownFirmware;

    #[inline]
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        [Self::V4_3, Self::V5_0, Self::V5_1]
            .into_iter()
            .find(|firmware| text == firmware.line() || text == firmware.title())
            .ok_or(UnknownFirmware)
    }
}

/// A model running a firmware line it is known to support.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Profile {
    /// The hardware model.
    model: Model,
    /// The firmware line.
    firmware: Firmware,
}

impl Profile {
    /// A profile, if `model` ships `firmware` in the simulator.
    ///
    /// # Errors
    ///
    /// [`UnsupportedProfile`] when the model has no such firmware profile.
    #[inline]
    pub fn new(model: Model, firmware: Firmware) -> Result<Self, UnsupportedProfile> {
        if model.firmware_lines().contains(&firmware) {
            Ok(Self { model, firmware })
        } else {
            Err(UnsupportedProfile { model, firmware })
        }
    }

    /// The model on its 5.1 seed firmware.
    #[inline]
    #[must_use]
    pub const fn latest(model: Model) -> Self {
        Self {
            model,
            firmware: Firmware::V5_1,
        }
    }

    /// The hardware model.
    #[inline]
    #[must_use]
    pub const fn model(self) -> Model {
        self.model
    }

    /// The firmware line.
    #[inline]
    #[must_use]
    pub const fn firmware(self) -> Firmware {
        self.firmware
    }
}

impl Default for Profile {
    #[inline]
    fn default() -> Self {
        Self::latest(Model::Kn1811)
    }
}

/// A model id that the simulator does not know.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct UnknownHardware;

impl fmt::Display for UnknownHardware {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("unknown model; expected KN-1811, KN-1010, KN-3810 or NC-3013")
    }
}

impl Error for UnknownHardware {}

/// A firmware line that the simulator does not know.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct UnknownFirmware;

impl fmt::Display for UnknownFirmware {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("unknown firmware; expected 4.3, 5.0 or 5.1")
    }
}

impl Error for UnknownFirmware {}

/// A model and firmware combination that has no profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct UnsupportedProfile {
    /// The requested model.
    pub model: Model,
    /// The requested firmware line.
    pub firmware: Firmware,
}

impl fmt::Display for UnsupportedProfile {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} has no {} profile", self.model, self.firmware.line())
    }
}

impl Error for UnsupportedProfile {}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use super::{Firmware, Model, Profile, UnknownHardware, UnsupportedProfile};

    /// Exactly the seven planned profiles exist: four 5.1 lines, KN-1811 4.3 and 5.0, KN-3810 4.3.
    #[test]
    fn profile_matrix() {
        let count = Model::ALL
            .into_iter()
            .flat_map(|model| model.firmware_lines().iter().map(move |fw| (model, *fw)))
            .filter(|&(model, firmware)| Profile::new(model, firmware).is_ok())
            .count();
        assert_eq!(count, 7);
        assert_eq!(
            Profile::new(Model::Kn1010, Firmware::V4_3),
            Err(UnsupportedProfile {
                model: Model::Kn1010,
                firmware: Firmware::V4_3
            })
        );
    }

    /// Model ids and firmware titles parse.
    #[test]
    fn parse_ids() {
        assert_eq!("KN-1811".parse(), Ok(Model::Kn1811));
        assert_eq!("nc-3013".parse(), Ok(Model::Nc3013));
        assert_eq!("4.3.9".parse(), Ok(Firmware::V4_3));
        assert_eq!("5.0".parse(), Ok(Firmware::V5_0));
        assert_eq!("KN-9999".parse::<Model>(), Err(UnknownHardware));
    }
}
