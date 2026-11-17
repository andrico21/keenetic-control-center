//! KeeneticOS firmware versions with a total order.

use core::{fmt, str::FromStr};

use thiserror::Error;

/// A firmware release stage, ordered `Alpha < Beta < Rc < Release`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum Stage {
    /// Alpha (development) build.
    Alpha,
    /// Beta build.
    Beta,
    /// Release candidate.
    Rc,
    /// Stable release.
    Release,
}

impl Stage {
    /// Parses a stage word used in `title`, case-insensitively.
    fn from_word(word: &str) -> Option<Self> {
        match word.to_ascii_lowercase().as_str() {
            "alpha" => Some(Self::Alpha),
            "beta" => Some(Self::Beta),
            "rc" => Some(Self::Rc),
            _ => None,
        }
    }

    /// Parses the stage letter used in `release` (`A`, `B`, `C`).
    const fn from_release_letter(letter: &str) -> Option<Self> {
        match letter.as_bytes() {
            [b'A' | b'a'] => Some(Self::Alpha),
            [b'B' | b'b'] => Some(Self::Beta),
            [b'C' | b'c'] => Some(Self::Release),
            _ => None,
        }
    }

    /// The word used when displaying a pre-release title.
    const fn word(self) -> &'static str {
        match self {
            Self::Alpha => "Alpha",
            Self::Beta => "Beta",
            Self::Rc => "RC",
            Self::Release => "",
        }
    }
}

/// A KeeneticOS firmware version.
///
/// Ordering compares `major`, `minor`, `stage`, `build`, then `patch`, so
/// `5.2 Beta 1 < 5.2.0` and `4.3.9 < 5.0.12`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
#[expect(
    clippy::module_name_repetitions,
    reason = "the protocol API is explicitly named FirmwareVersion"
)]
pub struct FirmwareVersion {
    /// Major line, e.g. `5`.
    pub major: u16,
    /// Minor line, e.g. `1`.
    pub minor: u16,
    /// Release stage.
    pub stage: Stage,
    /// Build within the stage: the patch level of a release (`5.1.3`) or the pre-release
    /// number (`5.2 Beta 1`).
    pub build: u16,
    /// Optional fourth component of a release title (`4.3.6.3`), otherwise 0.
    pub patch: u16,
}

impl FirmwareVersion {
    /// Creates a version from its ordering components.
    #[inline]
    #[must_use]
    pub const fn new(major: u16, minor: u16, stage: Stage, build: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            stage,
            build,
            patch,
        }
    }

    /// Returns the `(major, minor)` firmware line.
    #[inline]
    #[must_use]
    pub const fn line(self) -> (u16, u16) {
        (self.major, self.minor)
    }

    /// Parses a `show version` `release` string such as `5.01.A.0.0-0`.
    ///
    /// # Errors
    ///
    /// Returns [`FirmwareVersionError`] when the string is not `major.minor.letter.build[...]`.
    #[inline]
    pub fn from_release(release: &str) -> Result<Self, FirmwareVersionError> {
        let mut parts = release.trim().split('.');
        let major = parts.next().ok_or(FirmwareVersionError).and_then(number)?;
        let minor = parts.next().ok_or(FirmwareVersionError).and_then(number)?;
        let stage = parts
            .next()
            .and_then(Stage::from_release_letter)
            .ok_or(FirmwareVersionError)?;
        let build = parts.next().ok_or(FirmwareVersionError).and_then(number)?;
        let patch = match parts.next() {
            None => 0,
            Some(rest) => number(rest.split_once('-').map_or(rest, |(head, _tail)| head))?,
        };
        Ok(Self::new(major, minor, stage, build, patch))
    }

    /// Parses a `show version` `title` such as `5.1.3`, `4.3.6.3` or `5.2 Beta 1`.
    ///
    /// # Errors
    ///
    /// Returns [`FirmwareVersionError`] for any other shape.
    #[inline]
    pub fn from_title(title: &str) -> Result<Self, FirmwareVersionError> {
        let mut words = title.split_whitespace();
        let numeric = words.next().ok_or(FirmwareVersionError)?;
        let mut parts = numeric.split('.');
        let major = parts.next().ok_or(FirmwareVersionError).and_then(number)?;
        let minor = parts.next().ok_or(FirmwareVersionError).and_then(number)?;
        let third = parts.next().map(number).transpose()?;
        let fourth = parts.next().map(number).transpose()?;
        if parts.next().is_some() {
            return Err(FirmwareVersionError);
        }
        let version = match words.next() {
            None => Self::new(
                major,
                minor,
                Stage::Release,
                third.unwrap_or(0),
                fourth.unwrap_or(0),
            ),
            Some(word) => {
                let stage = Stage::from_word(word).ok_or(FirmwareVersionError)?;
                if third.is_some() {
                    return Err(FirmwareVersionError);
                }
                let build = words.next().map(number).transpose()?.unwrap_or(0);
                Self::new(major, minor, stage, build, 0)
            }
        };
        if words.next().is_some() {
            return Err(FirmwareVersionError);
        }
        Ok(version)
    }
}

impl FromStr for FirmwareVersion {
    type Err = FirmwareVersionError;

    /// Parses a `title` first and falls back to the `release` form.
    #[inline]
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::from_title(value).or_else(|_error| Self::from_release(value))
    }
}

impl fmt::Display for FirmwareVersion {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            major,
            minor,
            stage,
            build,
            patch,
        } = *self;
        match stage {
            Stage::Release if patch == 0 => write!(f, "{major}.{minor}.{build}"),
            Stage::Release => write!(f, "{major}.{minor}.{build}.{patch}"),
            Stage::Alpha | Stage::Beta | Stage::Rc => {
                write!(f, "{major}.{minor} {} {build}", stage.word())
            }
        }
    }
}

/// A firmware version string that matches neither the `title` nor the `release` form.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[error("firmware version is malformed")]
#[non_exhaustive]
pub struct FirmwareVersionError;

/// Parses one all-digit version component.
///
/// # Errors
///
/// Returns [`FirmwareVersionError`] for an empty, signed, non-digit, or oversized value.
fn number(text: &str) -> Result<u16, FirmwareVersionError> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(FirmwareVersionError);
    }
    text.parse().map_err(|_error| FirmwareVersionError)
}

#[cfg(test)]
mod tests {
    use core::cmp::Ordering;

    use super::{FirmwareVersion, FirmwareVersionError, Stage};

    #[test]
    #[expect(
        clippy::missing_panics_doc,
        clippy::missing_errors_doc,
        clippy::panic_in_result_fn,
        reason = "test assertions define the contract"
    )]
    fn parses_release_and_title_forms() -> Result<(), FirmwareVersionError> {
        assert_eq!(
            FirmwareVersion::from_release("5.01.A.0.0-0")?,
            FirmwareVersion::new(5, 1, Stage::Alpha, 0, 0)
        );
        assert_eq!(
            FirmwareVersion::from_release("4.03.C.6.3-1")?,
            FirmwareVersion::new(4, 3, Stage::Release, 6, 3)
        );
        assert_eq!(
            FirmwareVersion::from_title("5.2 Beta 1")?,
            FirmwareVersion::new(5, 2, Stage::Beta, 1, 0)
        );
        assert_eq!(
            FirmwareVersion::from_title("5.1.3")?.to_string(),
            "5.1.3".to_owned()
        );
        assert_eq!(
            FirmwareVersion::from_title("5.2 Beta 1")?.to_string(),
            "5.2 Beta 1".to_owned()
        );
        for malformed in [
            "",
            "5",
            "5.1.x",
            "+5.1.3",
            "5.1.3 Beta 1",
            "5.2 Gamma 1",
            "5.01.Z.0.0-0",
        ] {
            assert_eq!(
                malformed.parse::<FirmwareVersion>(),
                Err(FirmwareVersionError)
            );
        }
        Ok(())
    }

    /// A-19: versions order by major, minor, stage, build, then patch, and stages order
    /// alpha, beta, release candidate, release.
    #[test]
    #[expect(
        clippy::missing_panics_doc,
        reason = "test assertions define the contract"
    )]
    fn orders_every_field_in_declaration_order() {
        let stages = [Stage::Alpha, Stage::Beta, Stage::Rc, Stage::Release];
        assert!(stages.is_sorted_by(|lower, higher| lower < higher));
        let base = FirmwareVersion::new(4, 3, Stage::Beta, 6, 3);
        let ladder = [
            FirmwareVersion::new(4, 3, Stage::Beta, 6, 4),
            FirmwareVersion::new(4, 3, Stage::Beta, 7, 0),
            FirmwareVersion::new(4, 3, Stage::Rc, 0, 0),
            FirmwareVersion::new(4, 4, Stage::Alpha, 0, 0),
            FirmwareVersion::new(5, 0, Stage::Alpha, 0, 0),
        ];
        let mut lower = base;
        for higher in ladder {
            assert!(lower < higher, "{lower} < {higher}");
            assert_eq!(lower.cmp(&higher), Ordering::Less);
            assert_eq!(higher.partial_cmp(&lower), Some(Ordering::Greater));
            lower = higher;
        }
        // A more significant field outweighs every less significant one.
        assert!(
            FirmwareVersion::new(4, 3, Stage::Beta, u16::MAX, u16::MAX)
                < FirmwareVersion::new(4, 3, Stage::Rc, 0, 0)
        );
        assert!(
            FirmwareVersion::new(4, u16::MAX, Stage::Release, u16::MAX, u16::MAX)
                < FirmwareVersion::new(5, 0, Stage::Alpha, 0, 0)
        );
        assert_eq!(base.cmp(&base), Ordering::Equal);
    }
}
