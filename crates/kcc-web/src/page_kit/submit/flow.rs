//! How a submission goes on beyond its check and plan: which confirmations it asks for,
//! where its answers land, and whether a failed change reads the page back.
//!
//! The planned change's risk decides the confirmation: the kit asks for what that risk
//! needs unless the page's own confirmation already covers it.

use axum::response::Response;
use kcc_catalog::Risk;

use super::super::{confirm::Resubmit, respond::retarget};

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
    /// What confirming sends.
    resubmit: Resubmit,
    /// The risk to confirm once the values passed their check, before anything is read
    /// from the router, besides the planned change's own confirmation.
    first: Option<Risk>,
    /// The highest risk the page's own confirmation covers, checked before the
    /// submission.
    covered: Option<Risk>,
    /// Where its answers land.
    landing: Landing,
    /// Whether the page's region is read back after a failed change too.
    refresh_failed: bool,
}

impl Course {
    /// Confirmations at the planned risk, sending `resubmit`; every answer in the
    /// request's own target, nothing read back after a failure.
    pub(super) const fn new(resubmit: Resubmit) -> Self {
        Self {
            resubmit,
            first: None,
            covered: None,
            landing: Landing::Own,
            refresh_failed: false,
        }
    }

    /// Also asks for the confirmation `risk` needs before anything is read.
    pub(super) const fn asking_first(&mut self, risk: Risk) {
        self.first = Some(risk);
    }

    /// The page's own confirmation covers changes up to `risk`.
    pub(super) const fn covered_by_page(&mut self, risk: Risk) {
        self.covered = Some(risk);
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

    /// The risk to confirm before anything is read, if any.
    pub(super) const fn first(&self) -> Option<Risk> {
        self.first
    }

    /// Whether the page's own confirmation covers a change of `risk`.
    pub(super) fn covers(&self, risk: Risk) -> bool {
        self.covered.is_some_and(|covered| risk <= covered)
    }

    /// What confirming sends.
    pub(super) fn resubmit(&self) -> Resubmit {
        self.resubmit.clone()
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
