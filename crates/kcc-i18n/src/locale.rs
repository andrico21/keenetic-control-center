//! Supported locales and per-request locale negotiation.

use core::str::FromStr as _;

use unic_langid::{LanguageIdentifier, langid};

/// Name of the cookie that stores the locale a visitor picked in the Web UI.
pub const COOKIE_NAME: &str = "kcc_lang";

/// A locale with a complete message catalog.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Locale {
    /// English, the source of truth for every message.
    #[default]
    En,
    /// Russian.
    Ru,
    /// Ukrainian.
    Uk,
    /// German.
    De,
    /// Belarusian.
    Be,
    /// Kazakh.
    Kk,
}

impl Locale {
    /// Every supported locale, English first.
    pub const ALL: [Self; 6] = [Self::En, Self::Ru, Self::Uk, Self::De, Self::Be, Self::Kk];

    /// The BCP 47 language tag, also the directory name under `locales/`.
    #[inline]
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::En => "en",
            Self::Ru => "ru",
            Self::Uk => "uk",
            Self::De => "de",
            Self::Be => "be",
            Self::Kk => "kk",
        }
    }

    /// The Unicode language identifier used for plural rules and number formatting.
    #[inline]
    #[must_use]
    pub const fn language_identifier(self) -> LanguageIdentifier {
        match self {
            Self::En => langid!("en"),
            Self::Ru => langid!("ru"),
            Self::Uk => langid!("uk"),
            Self::De => langid!("de"),
            Self::Be => langid!("be"),
            Self::Kk => langid!("kk"),
        }
    }

    /// Maps a language tag such as `kk-KZ` or `be_BY` to a supported locale by its
    /// language subtag; returns `None` for malformed or unsupported tags.
    #[inline]
    #[must_use]
    pub fn from_tag(tag: &str) -> Option<Self> {
        let identifier = LanguageIdentifier::from_str(tag.trim()).ok()?;
        Self::ALL
            .into_iter()
            .find(|locale| locale.tag() == identifier.language.as_str())
    }

    /// Picks the supported locale with the highest quality value from an
    /// `Accept-Language` header; ties keep header order. Entries with `q=0`, wildcards,
    /// malformed quality values and unsupported languages are skipped.
    #[inline]
    #[must_use]
    pub fn from_accept_language(header: &str) -> Option<Self> {
        let mut best: Option<(u16, Self)> = None;
        for item in header.split(',') {
            let mut parts = item.split(';');
            let Some(tag) = parts.next() else {
                continue;
            };
            let mut quality = Some(1000_u16);
            for parameter in parts {
                if let Some((name, value)) = parameter.split_once('=')
                    && name.trim().eq_ignore_ascii_case("q")
                {
                    quality = parse_quality(value.trim());
                }
            }
            let (Some(weight), Some(locale)) = (quality, Self::from_tag(tag)) else {
                continue;
            };
            if weight > 0 && best.is_none_or(|(current, _)| weight > current) {
                best = Some((weight, locale));
            }
        }
        best.map(|(_, locale)| locale)
    }

    /// Negotiates the locale for one request, in priority order: the signed-in user's
    /// preference, the `kcc_lang` cookie, the `Accept-Language` header, the configured
    /// default, and finally English.
    #[inline]
    #[must_use]
    pub fn negotiate(
        user: Option<Self>,
        cookie: Option<&str>,
        accept_language: Option<&str>,
        config_default: Option<Self>,
    ) -> Self {
        user.or_else(|| cookie.and_then(Self::from_tag))
            .or_else(|| accept_language.and_then(Self::from_accept_language))
            .or(config_default)
            .unwrap_or(Self::En)
    }
}

/// Parses an HTTP quality value (`0`, `0.8`, `1.000`, ...) into thousandths.
fn parse_quality(value: &str) -> Option<u16> {
    let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
    if fraction.len() > 3 || !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    match whole {
        "0" => format!("{fraction:0<3}").parse().ok(),
        "1" if fraction.bytes().all(|byte| byte == b'0') => Some(1000),
        _ => None,
    }
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use super::{COOKIE_NAME, Locale, parse_quality};

    #[test]
    fn cookie_name_matches_the_web_contract() {
        assert_eq!(COOKIE_NAME, "kcc_lang", "the Web UI sets this cookie");
    }

    #[test]
    fn negotiation_follows_priority_order() {
        let header = Some("de");
        assert_eq!(
            Locale::negotiate(Some(Locale::Uk), Some("ru"), header, Some(Locale::Kk)),
            Locale::Uk,
            "user preference wins"
        );
        assert_eq!(
            Locale::negotiate(None, Some("ru"), header, Some(Locale::Kk)),
            Locale::Ru,
            "cookie beats Accept-Language"
        );
        assert_eq!(
            Locale::negotiate(None, Some("xx"), header, Some(Locale::Kk)),
            Locale::De,
            "unsupported cookie falls through to Accept-Language"
        );
        assert_eq!(
            Locale::negotiate(None, None, Some("fr"), Some(Locale::Kk)),
            Locale::Kk,
            "config default applies when nothing else matches"
        );
        assert_eq!(
            Locale::negotiate(None, None, None, None),
            Locale::En,
            "English is the last resort"
        );
    }

    #[test]
    fn accept_language_examples() {
        let cases = [
            ("kk-KZ,ru;q=0.8", Some(Locale::Kk)),
            ("be-BY", Some(Locale::Be)),
            ("fr", None),
            ("fr-FR,de;q=0.5,uk;q=0.9", Some(Locale::Uk)),
            ("ru;q=0.5,de;q=0.5", Some(Locale::Ru)),
            ("de;q=0,en;q=0.1", Some(Locale::En)),
            ("*,ru;q=0.2", Some(Locale::Ru)),
            ("ru;q=1.5,de", Some(Locale::De)),
            ("", None),
        ];
        for (header, expected) in cases {
            assert_eq!(Locale::from_accept_language(header), expected, "{header}");
        }
        assert_eq!(
            Locale::negotiate(None, None, Some("fr"), None),
            Locale::En,
            "fr negotiates to en"
        );
    }

    #[test]
    fn tags_round_trip() {
        for locale in Locale::ALL {
            assert_eq!(
                Locale::from_tag(locale.tag()),
                Some(locale),
                "{}",
                locale.tag()
            );
        }
        assert_eq!(
            Locale::from_tag("be_BY"),
            Some(Locale::Be),
            "underscore form"
        );
        assert_eq!(Locale::from_tag("RU"), Some(Locale::Ru), "case-insensitive");
        assert_eq!(Locale::from_tag("not a tag"), None, "malformed");
    }

    #[test]
    fn quality_values() {
        let cases = [
            ("1", Some(1000)),
            ("1.000", Some(1000)),
            ("0.8", Some(800)),
            ("0.125", Some(125)),
            ("0", Some(0)),
            ("1.5", None),
            ("0.1234", None),
            ("0.+8", None),
            ("abc", None),
        ];
        for (value, expected) in cases {
            assert_eq!(parse_quality(value), expected, "{value}");
        }
    }
}
