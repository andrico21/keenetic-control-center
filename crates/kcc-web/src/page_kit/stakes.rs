//! What a request puts at stake, and the guard that confirming it takes.
//!
//! A request's stakes are its catalog risk and whether it can change how kcc reaches the
//! router, which runs it inside the recovery timer. A page family turns the stakes into a
//! [`Guard`] once: the gate checks a submitted confirmation against that guard and the
//! dialog asks for exactly what it checks, so the two cannot disagree. A destructive
//! management change needs the router name typed and runs inside the timer; its one dialog
//! says both.

use kcc_catalog::{Risk, ValidatedRequest};

use super::{
    confirm::{Confirmation, Gate},
    family::Family,
};

/// What a request puts at stake.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Stakes {
    /// The request's risk.
    risk: Risk,
    /// Whether it can change how kcc reaches the router, so it runs inside the recovery
    /// timer.
    management: bool,
}

/// What confirming a request takes, and what its dialog explains.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Guard {
    /// The confirm button; the dialog describes the change.
    Write,
    /// The confirm button; the dialog explains the recovery timer.
    Management,
    /// The router name typed; the dialog says the change cannot be undone.
    Destructive,
    /// The router name typed; the dialog explains the recovery timer the change runs in.
    DestructiveManagement,
}

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
}
