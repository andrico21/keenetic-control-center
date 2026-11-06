//! Embedded Fluent catalogs and message formatting.
//!
//! The `.ftl` files are embedded with `include_bytes!` and decoded with
//! [`str::from_utf8`] when the catalogs are first used, so no translated text appears as
//! a Rust string literal. Bundles disable Unicode isolation marks because their output
//! goes straight into HTML, terminals and JSON.

use core::str;
use std::sync::LazyLock;

use fluent_bundle::{FluentArgs, FluentResource, concurrent::FluentBundle};

use crate::locale::Locale;

/// A Fluent message id from `locales/en/*.ftl`.
///
/// Values exist only as the generated constants in [`crate::keys`], so every key a
/// caller can name is a message of the English catalog.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MessageKey(&'static str);

impl MessageKey {
    /// Wraps a message id; only the generated [`crate::keys`] module calls this.
    pub(crate) const fn new(id: &'static str) -> Self {
        Self(id)
    }

    /// The Fluent message id, for example `common-save`.
    #[inline]
    #[must_use]
    pub const fn id(self) -> &'static str {
        self.0
    }
}

/// Why the embedded catalogs could not be loaded.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum LoadError {
    /// An embedded `.ftl` file is not valid UTF-8.
    #[error("locales/{}/{file} is not valid UTF-8", locale.tag())]
    InvalidUtf8 {
        /// The locale the file belongs to.
        locale: Locale,
        /// The file name, for example `web.ftl`.
        file: &'static str,
    },
    /// An embedded `.ftl` file has Fluent syntax errors.
    #[error("locales/{}/{file} has {errors} Fluent syntax error(s)", locale.tag())]
    InvalidFluent {
        /// The locale the file belongs to.
        locale: Locale,
        /// The file name, for example `web.ftl`.
        file: &'static str,
        /// How many syntax errors the parser reported.
        errors: usize,
    },
    /// An embedded `.ftl` file redefines a message already loaded for its locale.
    #[error("locales/{}/{file} redefines {errors} message(s)", locale.tag())]
    Duplicate {
        /// The locale the file belongs to.
        locale: Locale,
        /// The file name, for example `web.ftl`.
        file: &'static str,
        /// How many messages collided.
        errors: usize,
    },
}

/// The embedded `.ftl` files of one locale, as `(file name, contents)`.
type Sources = [(&'static str, &'static [u8])];

/// Embeds the seven catalog files of one locale directory.
macro_rules! locale_sources {
    ($lang:literal) => {
        &[
            (
                "common.ftl",
                include_bytes!(concat!("../locales/", $lang, "/common.ftl")),
            ),
            (
                "web.ftl",
                include_bytes!(concat!("../locales/", $lang, "/web.ftl")),
            ),
            (
                "cli.ftl",
                include_bytes!(concat!("../locales/", $lang, "/cli.ftl")),
            ),
            (
                "domains.ftl",
                include_bytes!(concat!("../locales/", $lang, "/domains.ftl")),
            ),
            (
                "migrate.ftl",
                include_bytes!(concat!("../locales/", $lang, "/migrate.ftl")),
            ),
            (
                "mcp.ftl",
                include_bytes!(concat!("../locales/", $lang, "/mcp.ftl")),
            ),
            (
                "errors.ftl",
                include_bytes!(concat!("../locales/", $lang, "/errors.ftl")),
            ),
        ]
    };
}

/// Every embedded catalog, one entry per [`Locale::ALL`] member.
const EMBEDDED: [(Locale, &Sources); 6] = [
    (Locale::En, locale_sources!("en")),
    (Locale::Ru, locale_sources!("ru")),
    (Locale::Uk, locale_sources!("uk")),
    (Locale::De, locale_sources!("de")),
    (Locale::Be, locale_sources!("be")),
    (Locale::Kk, locale_sources!("kk")),
];

/// The process-wide catalogs, parsed on first use.
static CATALOGS: LazyLock<Result<Catalogs, LoadError>> =
    LazyLock::new(|| Catalogs::load(&EMBEDDED));

/// Parsed Fluent bundles, one per locale.
struct Catalogs {
    /// The bundle of every loaded locale.
    bundles: Vec<(Locale, FluentBundle<FluentResource>)>,
}

impl Catalogs {
    /// Parses every source into one bundle per locale.
    ///
    /// # Errors
    ///
    /// Returns a [`LoadError`] for the first file that is not UTF-8, does not parse, or
    /// redefines a message.
    fn load(sources: &[(Locale, &Sources)]) -> Result<Self, LoadError> {
        let mut bundles = Vec::with_capacity(sources.len());
        for &(locale, files) in sources {
            let mut bundle =
                FluentBundle::new_concurrent(Vec::from([locale.language_identifier()]));
            bundle.set_use_isolating(false);
            for &(file, bytes) in files {
                let text = str::from_utf8(bytes)
                    .map_err(|_error| LoadError::InvalidUtf8 { locale, file })?;
                let resource =
                    FluentResource::try_new(text.to_owned()).map_err(|(_resource, errors)| {
                        LoadError::InvalidFluent {
                            locale,
                            file,
                            errors: errors.len(),
                        }
                    })?;
                bundle
                    .add_resource(resource)
                    .map_err(|errors| LoadError::Duplicate {
                        locale,
                        file,
                        errors: errors.len(),
                    })?;
            }
            bundles.push((locale, bundle));
        }
        Ok(Self { bundles })
    }

    /// Formats `key` with the bundle of `locale` alone, without fallback.
    ///
    /// Returns `None` when that bundle lacks the message or its value; formatting errors
    /// (such as a missing argument) still yield Fluent's best-effort text.
    fn format_exact(
        &self,
        locale: Locale,
        key: MessageKey,
        args: Option<&FluentArgs<'_>>,
    ) -> Option<(String, usize)> {
        let (_, bundle) = self.bundles.iter().find(|(loaded, _)| *loaded == locale)?;
        let pattern = bundle.get_message(key.0)?.value()?;
        let mut errors = Vec::new();
        let text = bundle
            .format_pattern(pattern, args, &mut errors)
            .into_owned();
        Some((text, errors.len()))
    }

    /// Formats `key` in `locale`, then in English, then as the bare message id.
    fn format(&self, locale: Locale, key: MessageKey, args: Option<&FluentArgs<'_>>) -> String {
        let formatted = self.format_exact(locale, key, args).or_else(|| {
            if cfg!(debug_assertions) {
                tracing::warn!(
                    locale = locale.tag(),
                    key = key.0,
                    "missing translation, falling back to en"
                );
            }
            self.format_exact(Locale::En, key, args)
        });
        if let Some((text, errors)) = formatted {
            if cfg!(debug_assertions) && errors > 0 {
                tracing::warn!(
                    locale = locale.tag(),
                    key = key.0,
                    errors,
                    "Fluent formatting errors"
                );
            }
            text
        } else {
            if cfg!(debug_assertions) {
                tracing::warn!(key = key.0, "message missing from the en catalog");
            }
            key.0.to_owned()
        }
    }
}

/// Parses the embedded catalogs now, so a broken build surfaces at startup instead of
/// as untranslated text on first use.
///
/// # Errors
///
/// Returns the [`LoadError`] of the first embedded file that cannot be loaded.
#[inline]
pub fn init() -> Result<(), LoadError> {
    CATALOGS.as_ref().map(|_| ()).map_err(Clone::clone)
}

/// Formats the message `key` in `locale` with optional Fluent arguments.
///
/// A message missing from `locale` falls back to English. In debug builds a missing
/// message or a formatting error is logged as a warning. If the catalogs failed to load
/// (see [`init`]), the bare message id is returned.
#[inline]
#[must_use]
pub fn tr(locale: Locale, key: MessageKey, args: Option<&FluentArgs<'_>>) -> String {
    CATALOGS.as_ref().map_or_else(
        |_error| key.0.to_owned(),
        |catalogs| catalogs.format(locale, key, args),
    )
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::error::Error;

    use fluent_bundle::FluentArgs;

    use super::{CATALOGS, Catalogs, EMBEDDED, LoadError, MessageKey, init, tr};
    use crate::{keys, locale::Locale};

    /// Fallible test result.
    type TestResult = Result<(), Box<dyn Error>>;

    /// Arguments covering every variable used by any message.
    fn all_arguments() -> FluentArgs<'static> {
        let mut args = FluentArgs::new();
        for name in [
            "user",
            "name",
            "url",
            "model",
            "version",
            "path",
            "field",
            "value",
            "page",
            "pages",
            "min",
            "max",
            "first",
            "last",
            "router",
            "method",
            "suggestion",
            "line",
            "column",
            "index",
            "issue",
        ] {
            args.set(name, "x");
        }
        for name in ["count", "current", "total", "minutes"] {
            args.set(name, 3_u32);
        }
        args
    }

    #[test]
    fn embedded_catalogs_load() -> TestResult {
        init()?;
        let loaded: Vec<Locale> = EMBEDDED.iter().map(|&(locale, _)| locale).collect();
        assert_eq!(loaded, Locale::ALL.to_vec(), "one catalog per locale");
        Ok(())
    }

    #[test]
    fn every_key_formats_in_every_locale() -> TestResult {
        let catalogs = CATALOGS.as_ref().map_err(Clone::clone)?;
        let args = all_arguments();
        for locale in Locale::ALL {
            for key in keys::ALL {
                let formatted = catalogs.format_exact(locale, key, Some(&args));
                let Some((text, errors)) = formatted else {
                    return Err(format!("{} lacks {}", locale.tag(), key.id()).into());
                };
                assert_eq!(errors, 0, "{} {}", locale.tag(), key.id());
                assert!(!text.trim().is_empty(), "{} {}", locale.tag(), key.id());
            }
        }
        Ok(())
    }

    #[test]
    fn output_has_no_isolation_marks() {
        let mut args = FluentArgs::new();
        args.set("user", "admin");
        assert_eq!(
            tr(Locale::En, keys::WEB_WELCOME, Some(&args)),
            "Welcome, admin!",
            "set_use_isolating(false) keeps HTML output clean"
        );
    }

    #[test]
    fn missing_message_falls_back_to_english() -> TestResult {
        let catalogs = Catalogs::load(&[
            (Locale::En, &[("a.ftl", b"only-en = English\n")]),
            (Locale::De, &[("a.ftl", b"other = Andere\n")]),
        ])?;
        let key = MessageKey::new("only-en");
        assert_eq!(
            catalogs.format(Locale::De, key, None),
            "English",
            "fallback"
        );
        let absent = MessageKey::new("absent");
        assert_eq!(
            catalogs.format(Locale::De, absent, None),
            "absent",
            "bare id"
        );
        Ok(())
    }

    #[test]
    fn broken_sources_are_reported() {
        let invalid = Catalogs::load(&[(Locale::En, &[("a.ftl", b"= no id\n")])]);
        assert!(
            matches!(
                invalid,
                Err(LoadError::InvalidFluent {
                    locale: Locale::En,
                    file: "a.ftl",
                    errors: 1
                })
            ),
            "syntax error"
        );
        let utf8 = Catalogs::load(&[(Locale::En, &[("a.ftl", b"a = \xff\n")])]);
        assert!(
            matches!(
                utf8,
                Err(LoadError::InvalidUtf8 {
                    locale: Locale::En,
                    file: "a.ftl"
                })
            ),
            "bad UTF-8"
        );
        let duplicate = Catalogs::load(&[(
            Locale::En,
            &[("a.ftl", b"a = one\n"), ("b.ftl", b"a = two\n")],
        )]);
        assert!(
            matches!(
                duplicate,
                Err(LoadError::Duplicate {
                    locale: Locale::En,
                    file: "b.ftl",
                    errors: 1
                })
            ),
            "duplicate message"
        );
    }
}
