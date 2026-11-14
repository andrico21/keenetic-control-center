//! When a submission asks for a confirmation, and where its answer lands.

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

/// `answer`, shown in `landing` when the submission names one.
pub(super) fn land(answer: Response, landing: Option<&'static str>) -> Response {
    match landing {
        Some(target) => retarget(answer, target),
        None => answer,
    }
}
