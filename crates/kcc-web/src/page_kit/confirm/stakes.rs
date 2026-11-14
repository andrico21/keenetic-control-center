//! The stakes of a request and the guard a page family puts on it: one decision for both
//! the gate and the dialog.

use kcc_catalog::{Risk, ValidatedRequest};
use kcc_i18n::{bundle::MessageKey, keys};

use super::{Confirmation, Gate, Guard, Prompt, Stakes};
use crate::page_kit::family::Family;

impl Stakes {
    /// A request of `risk`; a management one runs inside the recovery timer.
    pub(crate) const fn new(risk: Risk) -> Self {
        Self {
            risk,
            management: matches!(risk, Risk::Management),
        }
    }

    /// The stakes of a validated request: a management command anywhere in it runs the
    /// request inside the recovery timer, whatever its risk.
    pub(crate) const fn of(validated: &ValidatedRequest) -> Self {
        Self::new(validated.risk).with_management(validated.contains_management())
    }

    /// The same request, inside the recovery timer when `management`.
    pub(crate) const fn with_management(mut self, management: bool) -> Self {
        self.management |= management;
        self
    }

    /// The guard `family`'s pages put on the request; `None` when it runs at once.
    ///
    /// Reads always run, and a domain page's form already describes its write. A
    /// management change explains the recovery timer; a destructive one needs the router
    /// name typed, and explains the timer too when it also changes how kcc reaches the
    /// router.
    pub(crate) const fn guard(self, family: Family) -> Option<Guard> {
        match (self.risk, self.management, family) {
            (Risk::Read, _, _) | (Risk::Write, false, Family::Changes) => None,
            (Risk::Write, false, Family::Commands) => Some(Guard::Write),
            (Risk::Write | Risk::Management, _, _) => Some(Guard::Management),
            (Risk::Destructive | _, false, _) => Some(Guard::Destructive),
            (Risk::Destructive | _, true, _) => Some(Guard::DestructiveManagement),
        }
    }

    /// Whether the request may run on `router` with `confirmation` now, on a page of
    /// `family` that asks in its own dialog.
    ///
    /// Reads always run. A change the family confirms runs once confirmed; a destructive
    /// one only with the router's name typed exactly.
    pub(crate) fn gate(self, family: Family, confirmation: &Confirmation, router: &str) -> Gate {
        self.guard(family)
            .map_or(Gate::Run, |guard| guard.check(confirmation, router))
    }

    /// The dialog the request shows on `router`, in `family`'s words, before it runs, or
    /// `None` when `confirmation` lets it run now.
    ///
    /// One guard decides both, so the dialog asks for exactly what the gate checks.
    pub(crate) fn ask(
        self,
        family: Family,
        confirmation: &Confirmation,
        router: &str,
    ) -> Option<Prompt> {
        let guard = self.guard(family)?;
        match guard.check(confirmation, router) {
            Gate::Run => None,
            Gate::Ask { wrong_name } => {
                Some(Prompt::new(family, guard, router).with_wrong_name(wrong_name))
            }
        }
    }
}

impl Guard {
    /// Whether the router name must be typed.
    pub(crate) const fn needs_name(self) -> bool {
        match self {
            Self::Write | Self::Management => false,
            Self::Destructive | Self::DestructiveManagement => true,
        }
    }

    /// Whether `confirmation` passes the guard on `router`: the dialog's confirm button,
    /// and the router's name typed exactly when the guard needs it.
    pub(crate) fn check(self, confirmation: &Confirmation, router: &str) -> Gate {
        match (
            self.needs_name(),
            confirmation.name(),
            confirmation.confirmed(),
        ) {
            (false, _, true) => Gate::Run,
            (true, Some(name), true) if name == router => Gate::Run,
            (true, Some(_), true) => Gate::Ask { wrong_name: true },
            (false, _, false) | (true, Some(_) | None, _) => Gate::Ask { wrong_name: false },
        }
    }

    /// The title and text of the dialog confirming a change under the guard on a page of
    /// `family`; the texts take `$router`, the management ones also `$minutes`.
    pub(crate) const fn words(self, family: Family) -> (MessageKey, MessageKey) {
        match (family, self) {
            (Family::Commands, Self::Write) => (
                keys::WEB_EXPLORER_CONFIRM_WRITE_TITLE,
                keys::WEB_EXPLORER_CONFIRM_WRITE_TEXT,
            ),
            (Family::Commands, Self::Management | Self::DestructiveManagement) => (
                keys::WEB_EXPLORER_CONFIRM_MANAGEMENT_TITLE,
                keys::WEB_EXPLORER_CONFIRM_MANAGEMENT_TEXT,
            ),
            (Family::Commands, Self::Destructive) => (
                keys::WEB_EXPLORER_CONFIRM_DESTRUCTIVE_TITLE,
                keys::WEB_EXPLORER_CONFIRM_DESTRUCTIVE_TEXT,
            ),
            (Family::Changes, Self::Write) => (
                keys::WEB_KIT_CONFIRM_WRITE_TITLE,
                keys::WEB_KIT_CONFIRM_WRITE_TEXT,
            ),
            (Family::Changes, Self::Management | Self::DestructiveManagement) => (
                keys::WEB_KIT_CONFIRM_MANAGEMENT_TITLE,
                keys::WEB_KIT_CONFIRM_MANAGEMENT_TEXT,
            ),
            (Family::Changes, Self::Destructive) => (
                keys::WEB_KIT_CONFIRM_DESTRUCTIVE_TITLE,
                keys::WEB_KIT_CONFIRM_DESTRUCTIVE_TEXT,
            ),
        }
    }
}
