//! How a submission goes on beyond its check and plan: when it asks for a confirmation,
//! where its answers land, and whether a failed change reads the page back.

use core::mem;

use axum::response::Response;
use kcc_catalog::Risk;

use super::super::{confirm::Resubmit, respond::retarget};

/// When the submission asks for a confirmation.
pub(super) enum Ask {
    /// Never: the change's risk needs none.
    Never,
    /// Once the values passed their check, before anything is read from the router, at
    /// `risk`.
    First {
        /// The risk the confirmation is for.
        risk: Risk,
        /// What confirming sends.
        resubmit: Resubmit,
    },
    /// Once the change is planned, at the planned risk.
    Planned(Resubmit),
}

/// Where the submission's answers land instead of the request's own target.
#[derive(Clone, Copy)]
enum Landing {
    /// Every answer stays in the request's own target.
    Own,
    /// Every answer to the change, refused or run, lands in the target.
    Every(&'static str),
    /// Only the answer to a change that ran lands in the target; a refusal stays.
    Run(&'static str),
}

/// The submission's course.
pub(super) struct Course {
    /// When the submission asks for a confirmation.
    ask: Ask,
    /// Where its answers land.
    landing: Landing,
    /// Whether the page's region is read back after a failed change too.
    refresh_failed: bool,
}

impl Course {
    /// No confirmation, every answer in the request's own target, nothing read back after
    /// a failure.
    pub(super) const fn new() -> Self {
        Self {
            ask: Ask::Never,
            landing: Landing::Own,
            refresh_failed: false,
        }
    }

    /// Asks as `ask` says.
    pub(super) fn asking(&mut self, ask: Ask) {
        self.ask = ask;
    }

    /// Every answer to the change lands in `target`.
    pub(super) const fn landing_in(&mut self, target: &'static str) {
        self.landing = Landing::Every(target);
    }

    /// The answer to a change that ran lands in `target`.
    pub(super) const fn landing_run_in(&mut self, target: &'static str) {
        self.landing = Landing::Run(target);
    }

    /// Reads the page's region back after a failed change too.
    pub(super) const fn refreshing_after_failure(&mut self) {
        self.refresh_failed = true;
    }

    /// Whether the page's region is read back after a change that ran, `succeeded` or not.
    pub(super) const fn reads_back(&self, succeeded: bool) -> bool {
        succeeded || self.refresh_failed
    }

    /// The confirmation to ask for before anything is read, taken from the course.
    pub(super) fn first(&mut self) -> Option<(Risk, Resubmit)> {
        match mem::replace(&mut self.ask, Ask::Never) {
            Ask::First { risk, resubmit } => Some((risk, resubmit)),
            later @ (Ask::Never | Ask::Planned(_)) => {
                self.ask = later;
                None
            }
        }
    }

    /// The confirmation to ask for once the change is planned, taken from the course.
    pub(super) fn planned(&mut self) -> Option<Resubmit> {
        match mem::replace(&mut self.ask, Ask::Never) {
            Ask::Planned(resubmit) => Some(resubmit),
            Ask::Never
            | Ask::First {
                risk: _,
                resubmit: _,
            } => None,
        }
    }

    /// `answer` to a change refused before it ran, where it lands.
    pub(super) fn refused(&self, answer: Response) -> Response {
        match self.landing {
            Landing::Every(target) => retarget(answer, target),
            Landing::Own | Landing::Run(_) => answer,
        }
    }

    /// `answer` to a change that ran, where it lands.
    pub(super) fn ran(&self, answer: Response) -> Response {
        match self.landing {
            Landing::Every(target) | Landing::Run(target) => retarget(answer, target),
            Landing::Own => answer,
        }
    }
}
