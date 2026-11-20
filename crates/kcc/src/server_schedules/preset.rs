//! The scheduled preset apply: a stored preset, in Merge mode, onto the schedule's router;
//! kept unsaved after verification, rolled back after a failure.
//!
//! What holds the router at each stage of a run:
//!
//! - The whole run holds a workflow bracket guard, from planning to its last read.
//! - Planning reads the router with the owner's role narrowed to the router and the
//!   preset's source router, against a fresh inventory, and refuses a plan that needs
//!   input, has a management-phase line or sets a WireGuard private key. Nothing is leased,
//!   armed or sent.
//! - The router's lease is reserved before the applier's job starts; a busy lease or job
//!   slot makes the run busy, and the scheduler tries again with a new plan.
//! - The applier backs the router up, arms its fail-safe timer, sends the lines and
//!   verifies them, all under the lease.
//! - Verified: the timer is disarmed and the changes stay unsaved (`keep_unsaved`); the
//!   lease ends with the applier.
//! - Not verified: the run rolls the router back to its saved configuration (`rollback`,
//!   under `Migrate`); the lease ends with the applier.
//! - A rollback or disarm that fails keeps the applier, and so the lease, until the
//!   fail-safe timer has run out on the apply clock; `show last-change` then tells whether
//!   the router restored its saved configuration.
//! - A preparation that failed leaves no applier, and nothing is rolled back. When the
//!   fail-safe timer may still be armed (its arming or its cleanup was not confirmed), it
//!   is reported as possibly armed and the applier's job keeps the lease until the timer
//!   has run out on the apply clock; the run ends with the job. Otherwise the lease ends
//!   with the preparation.
//!
//! Nothing is ever saved, and Mirror mode is never used.

mod finish;
mod prepare;
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "test code is not rendered API documentation"
)]
mod tests;

use kcc_app::{
    audit::{Actor, ActorKind},
    permissions::Role,
};
use kcc_migrate::{apply::ApplyRequest, presets::unattended::UnattendedRefusal};

use super::actions::{ActionDeps, ActionResult};

/// A preset schedule's router, preset and documentation-tier acknowledgement, as a
/// schedule form submits them or as a schedule stores them.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Target<'target> {
    /// The router the preset is applied to.
    router: &'target str,
    /// The stored preset's id.
    preset_id: &'target str,
    /// The owner acknowledged a documentation-based firmware line on the router.
    ack_documentation_tier: bool,
}

impl<'target> Target<'target> {
    /// Preset `preset_id` onto `router`, with or without the acknowledgement.
    pub(crate) const fn new(
        router: &'target str,
        preset_id: &'target str,
        ack_documentation_tier: bool,
    ) -> Self {
        Self {
            router,
            preset_id,
            ack_documentation_tier,
        }
    }
}

/// Why a preset schedule cannot run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PresetRefusal {
    /// The role lacks `Read` or `Migrate` on the router or on the preset's source router.
    Forbidden,
    /// The preset is missing or cannot be opened.
    Unavailable,
    /// The router could not be read.
    Router,
    /// The router's firmware is older than the preset's, or not supported.
    Firmware,
    /// The router runs a documentation-based firmware line that was not acknowledged.
    DocumentationTier,
    /// A preset item needs operator input or conflicts with the router.
    NotReady,
    /// The plan has a management-phase line.
    ManagementLines,
    /// The plan sets a WireGuard private key.
    WireGuardKey,
}

impl PresetRefusal {
    /// The machine-read code.
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::Forbidden => "forbidden",
            Self::Unavailable => "preset_unavailable",
            Self::Router => "router",
            Self::Firmware => "firmware",
            Self::DocumentationTier => "documentation_tier",
            Self::NotReady => "not_ready",
            Self::ManagementLines => "management_lines",
            Self::WireGuardKey => "wireguard_key",
        }
    }

    /// How a run that met the refusal ends: failed for a refused role or an unreadable
    /// router, skipped for a preset that may not run unattended.
    const fn result(self) -> ActionResult {
        let code = self.code();
        match self {
            Self::Forbidden | Self::Router => ActionResult::Failed { code, job: None },
            Self::Unavailable
            | Self::Firmware
            | Self::DocumentationTier
            | Self::NotReady
            | Self::ManagementLines
            | Self::WireGuardKey => ActionResult::Skipped {
                reason: code,
                job: None,
            },
        }
    }
}

impl From<UnattendedRefusal> for PresetRefusal {
    fn from(refusal: UnattendedRefusal) -> Self {
        match refusal {
            UnattendedRefusal::ManagementLines => Self::ManagementLines,
            UnattendedRefusal::WireGuardKey => Self::WireGuardKey,
            UnattendedRefusal::NotReady | _ => Self::NotReady,
        }
    }
}

/// A preset apply ready to start.
struct Prepared {
    /// The protected request, on the action's apply clock, with the narrowed role.
    request: ApplyRequest,
    /// The preset's source router, when it names one.
    source: Option<String>,
}

/// Checks that a preset schedule of `target` with `role` could run now.
///
/// It plans as a run does (a fresh inventory of the router, the Merge plan, the refusals
/// of an unattended apply) without leasing or changing the router.
///
/// The schedule forms call it when a preset schedule is created or edited; on success it
/// answers the preset's source router, which the schedule store checks the role on
/// (`NewSchedule::with_preset_source`).
///
/// # Errors
///
/// Why the schedule could not run.
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned
// router session. Apart from that, reads.
pub(crate) async fn eligible(
    deps: &ActionDeps,
    role: &Role,
    target: Target<'_>,
) -> Result<Option<String>, PresetRefusal> {
    let actor = Actor::new(ActorKind::System, "schedule:eligibility".to_owned());
    prepare::request(deps, target, (role, actor))
        .await
        .map(|prepared| prepared.source)
}

/// Applies `target`'s preset with the owner's `role` as `actor` and ends the run: kept
/// unsaved after verification, rolled back after a failure; the result carries the
/// applier's job.
// NOT cancel-safe: dropped while the applier changes the router, the router keeps its armed
// fail-safe timer and the run's outcome is lost.
pub(super) async fn apply(
    deps: &ActionDeps,
    target: Target<'_>,
    (role, actor): (&Role, Actor),
) -> ActionResult {
    let _bracket = deps.workflow().brackets().enter();
    match prepare::request(deps, target, (role, actor)).await {
        Ok(prepared) => finish::run(deps, prepared.request).await,
        Err(refusal) => refusal.result(),
    }
}
