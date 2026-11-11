//! How a family of pages confirms and words its changes.
//!
//! The command explorer and the consoles run raw commands, so every change asks first and
//! the messages speak of commands. A domain page runs a curated operation its form already
//! describes, so only management and destructive changes ask. Everything else in the kit
//! is shared, so a page family picks its [`Family`] once and passes it to the
//! confirmations and the outcomes.

use kcc_catalog::Risk;
use kcc_i18n::{bundle::MessageKey, keys};

use super::{
    confirm::{Confirmation, Gate, Prompt},
    stakes::{Guard, Stakes},
};

/// A family of pages: its confirmation policy and its messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Family {
    /// The command explorer and the consoles: every change asks, messages speak of
    /// commands.
    Commands,
    /// The domain pages: management and destructive changes ask, messages speak of
    /// changes.
    Changes,
}

impl Family {
    /// Whether a request of `risk` on `router` with `confirmation` may run now, for a page
    /// that asks in its own dialog.
    ///
    /// Reads always run. A change the family confirms runs once confirmed; a destructive
    /// one only with the router's name typed exactly.
    pub(crate) fn gate(self, risk: Risk, confirmation: &Confirmation, router: &str) -> Gate {
        Stakes::new(risk)
            .guard(self)
            .map_or(Gate::Run, |guard| guard.check(confirmation, router))
    }

    /// The dialog a request with `stakes` on `router` shows before it runs, or `None` when
    /// `confirmation` lets it run now.
    ///
    /// One guard decides both, so the dialog asks for exactly what the gate checks.
    pub(crate) fn ask(
        self,
        stakes: Stakes,
        confirmation: &Confirmation,
        router: &str,
    ) -> Option<Prompt> {
        let guard = stakes.guard(self)?;
        match guard.check(confirmation, router) {
            Gate::Run => None,
            Gate::Ask { wrong_name } => {
                Some(Prompt::new(self, guard, router).with_wrong_name(wrong_name))
            }
        }
    }

    /// The title and text of the dialog confirming a change under `guard`; the texts take
    /// `$router`, the management ones also `$minutes`.
    pub(crate) const fn dialog(self, guard: Guard) -> (MessageKey, MessageKey) {
        match (self, guard) {
            (Self::Commands, Guard::Write) => (
                keys::WEB_EXPLORER_CONFIRM_WRITE_TITLE,
                keys::WEB_EXPLORER_CONFIRM_WRITE_TEXT,
            ),
            (Self::Commands, Guard::Management | Guard::DestructiveManagement) => (
                keys::WEB_EXPLORER_CONFIRM_MANAGEMENT_TITLE,
                keys::WEB_EXPLORER_CONFIRM_MANAGEMENT_TEXT,
            ),
            (Self::Commands, Guard::Destructive) => (
                keys::WEB_EXPLORER_CONFIRM_DESTRUCTIVE_TITLE,
                keys::WEB_EXPLORER_CONFIRM_DESTRUCTIVE_TEXT,
            ),
            (Self::Changes, Guard::Write) => (
                keys::WEB_KIT_CONFIRM_WRITE_TITLE,
                keys::WEB_KIT_CONFIRM_WRITE_TEXT,
            ),
            (Self::Changes, Guard::Management | Guard::DestructiveManagement) => (
                keys::WEB_KIT_CONFIRM_MANAGEMENT_TITLE,
                keys::WEB_KIT_CONFIRM_MANAGEMENT_TEXT,
            ),
            (Self::Changes, Guard::Destructive) => (
                keys::WEB_KIT_CONFIRM_DESTRUCTIVE_TITLE,
                keys::WEB_KIT_CONFIRM_DESTRUCTIVE_TEXT,
            ),
        }
    }

    /// The confirm button.
    pub(crate) const fn confirm(self) -> MessageKey {
        match self {
            Self::Commands => keys::WEB_EXPLORER_CONFIRM,
            Self::Changes => keys::WEB_KIT_CONFIRM,
        }
    }

    /// Headline of a completed request; `unsaved` when the router has unsaved changes now.
    pub(crate) const fn done(self, unsaved: bool) -> MessageKey {
        match (self, unsaved) {
            (Self::Commands, false) => keys::WEB_EXPLORER_DONE,
            (Self::Commands, true) => keys::WEB_EXPLORER_DONE_UNSAVED,
            (Self::Changes, false) => keys::WEB_KIT_DONE,
            (Self::Changes, true) => keys::WEB_KIT_DONE_UNSAVED,
        }
    }

    /// Headline of a change after which the router's state is unknown: a reboot, a reset.
    pub(crate) const fn done_terminal(self) -> MessageKey {
        match self {
            Self::Commands => keys::WEB_EXPLORER_DONE,
            Self::Changes => keys::WEB_KIT_DONE_TERMINAL,
        }
    }

    /// Headline of a request stopped before anything was sent.
    pub(crate) const fn invalid(self) -> MessageKey {
        match self {
            Self::Commands => keys::WEB_EXPLORER_INVALID,
            Self::Changes => keys::WEB_KIT_INVALID,
        }
    }

    /// The router refused the request.
    pub(crate) const fn rejected(self) -> MessageKey {
        match self {
            Self::Commands => keys::WEB_EXPLORER_REJECTED,
            Self::Changes => keys::WEB_KIT_REJECTED,
        }
    }

    /// Another session changed the router first.
    pub(crate) const fn conflict(self) -> MessageKey {
        match self {
            Self::Commands => keys::WEB_EXPLORER_CONFLICT,
            Self::Changes => keys::WEB_KIT_CONFLICT,
        }
    }

    /// The request failed for another reason.
    pub(crate) const fn failed(self) -> MessageKey {
        match self {
            Self::Commands => keys::WEB_EXPLORER_FAILED,
            Self::Changes => keys::WEB_KIT_FAILED,
        }
    }

    /// The router did not answer.
    pub(crate) const fn unreachable(self) -> MessageKey {
        match self {
            Self::Commands => keys::WEB_EXPLORER_UNREACHABLE,
            Self::Changes => keys::WEB_KIT_UNREACHABLE,
        }
    }

    /// The router does not know the resource.
    pub(crate) const fn not_found(self) -> MessageKey {
        match self {
            Self::Commands => keys::WEB_EXPLORER_NOT_FOUND,
            Self::Changes => keys::WEB_KIT_NOT_FOUND,
        }
    }
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use kcc_catalog::Risk;

    use super::Family;
    use crate::page_kit::confirm::{Confirmation, Gate};

    #[test]
    fn each_risk_needs_its_confirmation() {
        let none = Confirmation::default();
        let confirmed = Confirmation::new(Some("yes"), None);
        let named = Confirmation::new(Some("yes"), Some(" home "));
        let misnamed = Confirmation::new(Some("yes"), Some("Home"));
        let family = Family::Commands;
        assert_eq!(
            family.gate(Risk::Read, &none, "home"),
            Gate::Run,
            "reads run"
        );
        assert_eq!(
            family.gate(Risk::Write, &none, "home"),
            Gate::Ask { wrong_name: false },
            "writes ask"
        );
        assert_eq!(
            family.gate(Risk::Management, &confirmed, "home"),
            Gate::Run,
            "confirmed"
        );
        assert_eq!(
            family.gate(Risk::Destructive, &confirmed, "home"),
            Gate::Ask { wrong_name: false },
            "destructive needs the name"
        );
        assert_eq!(
            family.gate(Risk::Destructive, &misnamed, "home"),
            Gate::Ask { wrong_name: true },
            "names are exact"
        );
        assert_eq!(
            family.gate(Risk::Destructive, &named, "home"),
            Gate::Run,
            "named"
        );
    }

    #[test]
    fn domain_pages_ask_only_for_guarded_changes() {
        let none = Confirmation::default();
        let confirmed = Confirmation::new(Some("yes"), None);
        let named = Confirmation::new(Some("yes"), Some("home"));
        let family = Family::Changes;
        assert_eq!(
            family.gate(Risk::Write, &none, "home"),
            Gate::Run,
            "the form describes a write"
        );
        assert_eq!(
            family.gate(Risk::Management, &none, "home"),
            Gate::Ask { wrong_name: false },
            "management asks"
        );
        assert_eq!(
            family.gate(Risk::Management, &confirmed, "home"),
            Gate::Run,
            "confirmed management runs"
        );
        assert_eq!(
            family.gate(Risk::Destructive, &confirmed, "home"),
            Gate::Ask { wrong_name: false },
            "destructive needs the name"
        );
        assert_eq!(
            family.gate(Risk::Destructive, &named, "home"),
            Gate::Run,
            "named"
        );
    }
}
