//! How an outcome shows: the tone of its notice and toasts, and the fragment of a page's
//! outcome region.

use askama::Template;
use kcc_i18n::{keys, locale::Locale};

use super::Outcome;
use crate::{
    page::{Localize as _, Shell},
    page_kit::context::fragment_shell,
};

/// The tone of a notice or a toast.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Tone {
    /// Done as asked.
    Success,
    /// Under way, or nothing to report.
    Info,
    /// Done, with something to look at.
    Warning,
    /// Not done.
    Error,
}

impl Tone {
    /// The `data-tone` value.
    pub(crate) const fn value(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
        }
    }
}

/// The outcome fragment of a page's outcome region.
#[derive(Template)]
#[template(path = "partials/kit_outcome.html")]
pub(super) struct OutcomeView {
    /// Locale carrier.
    shell: Shell,
    /// The outcome.
    outcome: Outcome,
}

localized!(OutcomeView);

impl OutcomeView {
    /// The fragment of `outcome` in `locale`.
    pub(super) const fn new(locale: Locale, outcome: Outcome) -> Self {
        Self {
            shell: fragment_shell(locale),
            outcome,
        }
    }
}
