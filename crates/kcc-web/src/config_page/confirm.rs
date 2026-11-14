//! The confirmation of this page's destructive actions: rolling the fail-safe timer back,
//! deleting a backup and restoring one as the router's saved configuration.
//!
//! Each needs the router name typed, exactly as the kit's destructive confirmation does
//! (`Family::Changes`), with a dialog that says what this action does. The server decides
//! on every request; showing the dialog trusts nothing.

use axum::response::Response;
use fluent_bundle::FluentArgs;
use kcc_catalog::Risk;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};

use crate::{
    page::Localize as _,
    page_kit::{
        confirm::{self, Ask, Confirmation, Gate, Resubmit, Stakes, Typed},
        family::Family,
    },
};

/// The dialog asking for the router name before a destructive action.
pub(crate) struct ConfirmDialog(confirm::Dialog);

/// The words of one confirmation: title, text and button.
pub(crate) type Words = (MessageKey, MessageKey, MessageKey);

/// Whether `pairs` confirm a destructive action on `router`: the dialog's button and the
/// router name typed exactly.
pub(crate) fn gate(pairs: &[(String, String)], router: &str) -> Gate {
    Stakes::new(Risk::Destructive).gate(Family::Changes, &Confirmation::from_pairs(pairs), router)
}

impl ConfirmDialog {
    /// The dialog in `locale` posting to `action`, its object in the query, in `words`
    /// whose variables come from `args`.
    pub(crate) fn new(
        locale: Locale,
        action: String,
        (words, args): (Words, &FluentArgs<'_>),
    ) -> Self {
        let (title, text, button) = words;
        let said = confirm::Words::new(
            tr(locale, title, Some(args)),
            tr(locale, text, Some(args)),
            tr(locale, button, None),
        );
        Self(confirm::Dialog::new(
            locale,
            said,
            Resubmit::new(action, "#page-outcome"),
        ))
    }

    /// Shows the dialog, with the mismatch error when the typed name of `router` was
    /// wrong.
    pub(crate) fn ask(self, wrong_name: bool, router: &str) -> Response {
        let Self(dialog) = self;
        let locale = dialog.shell().locale();
        let error = if wrong_name {
            let mut args = FluentArgs::new();
            args.set("router", router.to_owned());
            tr(locale, keys::WEB_EXPLORER_CONFIRM_NAME_ERROR, Some(&args))
        } else {
            String::new()
        };
        dialog
            .asking(Ask::Typed(Typed::router(locale).with_error(error)))
            .show()
    }
}
