//! The second acknowledgement of the storage page: ejecting or initializing the drive
//! Entware runs from.
//!
//! The domain refuses such a change until it is acknowledged. The page answers that
//! refusal with a second dialog, after the typed router name of the first: confirming it
//! sends the request again with `entware_ok=yes`, and only that request plans the change
//! with the acknowledgement.

use core::future::ready;

use axum::response::{IntoResponse as _, Response};
use kcc_domain::DomainError;
use kcc_i18n::{bundle::tr, keys, locale::Locale};

use super::shared::{refused, value};
use crate::{
    markup::Rendered,
    page_kit::{
        confirm::{Ask, Dialog, Resubmit, Typed, Words},
        outcome::{Failure, Outcome},
        request::{missing, with_query},
        respond::changed,
        submit::{self, Invalid, unplanned::Unplanned},
    },
};

/// The query pair of the second acknowledgement.
const ACKNOWLEDGED: (&str, &str) = ("entware_ok", "yes");

/// Whether `pairs` carry the second acknowledgement.
pub(super) fn acknowledged(pairs: &[(String, String)]) -> bool {
    value(pairs, ACKNOWLEDGED.0) == Some(ACKNOWLEDGED.1)
}

/// What the storage action does to the medium, in the second dialog's words.
#[derive(Clone, Copy)]
pub(super) enum Act {
    /// Eject.
    Eject,
    /// Initialize with ext4.
    Initialize,
}

/// A storage action's form, which answers the Entware drive with the second dialog.
///
/// Any other refusal shows in the outcome region, and a started initialize says that the
/// router initializes in the background.
pub(super) struct EntwareGuard {
    /// The action's endpoint.
    path: String,
    /// The medium.
    media: String,
    /// What the action does.
    act: Act,
}

impl EntwareGuard {
    /// The guard of `act` on `media`, sent to `path`.
    pub(super) const fn new(path: String, media: String, act: Act) -> Self {
        Self { path, media, act }
    }

    /// The second dialog: the domain's reason, the router name typed again, and the
    /// request sent again with the acknowledgement.
    fn dialog(&self, locale: Locale) -> Response {
        let button = match self.act {
            Act::Eject => keys::WEB_SYSTEM_ENTWARE_DRIVE_EJECT,
            Act::Initialize => keys::WEB_SYSTEM_ENTWARE_DRIVE_INITIALIZE,
        };
        let words = Words::new(
            tr(locale, keys::WEB_SYSTEM_ENTWARE_DRIVE_TITLE, None),
            tr(locale, keys::DOMAINS_ENTWARE_DRIVE_IN_USE, None),
            tr(locale, button, None),
        );
        let again = with_query(&self.path, &[("media", self.media.as_str()), ACKNOWLEDGED]);
        Dialog::new(locale, words, Resubmit::new(again, "#page-outcome"))
            .with_text_key(keys::DOMAINS_ENTWARE_DRIVE_IN_USE)
            .asking(Ask::Typed(Typed::router(locale)))
            .show()
    }
}

impl submit::Form for EntwareGuard {
    fn answer_invalid(self, _invalid: Invalid, _locale: Locale) -> Response {
        missing().into_response()
    }

    fn answer_refused(self, failure: Failure, locale: Locale) -> Response {
        refused(&failure, locale)
    }

    fn answer_unplanned(
        self,
        unplanned: Unplanned<'_>,
        locale: Locale,
    ) -> impl Future<Output = Response> {
        let answer = if matches!(unplanned.error(), DomainError::EntwareDriveInUse) {
            self.dialog(locale)
        } else {
            refused(&unplanned.into_failure(), locale)
        };
        ready(answer)
    }

    fn answer_changed(
        self,
        outcome: Outcome,
        refreshed: Option<Rendered>,
        locale: Locale,
    ) -> Response {
        let recast = match self.act {
            Act::Initialize if outcome.succeeded() => {
                let headline = tr(locale, keys::WEB_SYSTEM_ENTWARE_PREPARE_STARTED, None);
                Outcome::done(headline, outcome.unsaved())
            }
            Act::Initialize | Act::Eject => outcome,
        };
        changed(recast, refreshed, None, locale)
    }
}
