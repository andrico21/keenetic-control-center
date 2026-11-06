//! Internationalization: message catalogs and locale selection.
//!
//! Every user-visible string lives in `locales/<lang>/*.ftl` (Project Fluent). English is
//! the source of truth; `cargo xtask i18n-gen` turns its message ids into the constants in
//! [`keys`], so a caller naming a message that does not exist fails to compile, and
//! `cargo xtask i18n-check` keeps every other locale in step with English.
//!
//! - [`locale::Locale`] lists the supported locales and negotiates one per request.
//! - [`bundle::tr`] formats a message, falling back to English.
//! - [`format`](mod@format) writes numbers, sizes, rates and durations the way each locale does.

pub mod bundle;
pub mod format;
pub mod keys;
pub mod locale;
