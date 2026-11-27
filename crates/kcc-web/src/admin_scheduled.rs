//! Scheduled actions at `/ui/admin/scheduled` (`ManageSchedules`).
//!
//! The page lists the weekly scheduled actions on the routers the role sees, with each
//! one's next slot and last run, and creates, edits, pauses, resumes, deletes and runs
//! them now. A schedule does one of four things: put a registered client under a
//! connection policy, apply a stored preset (Merge only), back up the startup
//! configuration or restart the router. Scheduled changes are never saved, so a router
//! restart undoes them.
//!
//! `kcc serve` attaches its scheduler with
//! [`WebState::with_schedules`](crate::WebState::with_schedules): creating, editing and
//! resuming ask it first whether the action can run ([`ScheduleControl::check`]), and
//! "Run now" goes through it. Without a scheduler the page still lists, pauses and deletes
//! schedules and says that they run only in `kcc serve`.

extern crate alloc;

mod choices;
mod dialog;
pub(crate) mod editor;
mod form;
pub(crate) mod next;
pub(crate) mod page;
mod rows;
pub(crate) mod run_now;
mod text;
pub(crate) mod toggle;

use alloc::collections::BTreeMap;
use core::{fmt, pin::Pin};

use kcc_app::{
    permissions::Role,
    schedules::{
        ledger::RunRecord,
        model::{Action, Schedule},
    },
};
use serde::Deserialize;

/// A schedule named by its id: the query of a dialog, the form of a table action.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ScheduleId {
    /// The schedule's id.
    id: String,
}

/// One schedule the page lists, with its last run.
struct Listed {
    /// The schedule.
    schedule: Schedule,
    /// What people read for its router: the display name, else the id.
    router_name: String,
    /// Its last run, if it ran.
    last: Option<RunRecord>,
}

/// The future of [`ScheduleControl::check`]: the preset's source router, or the refusal.
pub type Checked<'call> =
    Pin<Box<dyn Future<Output = Result<Option<String>, ScheduleRefusal>> + Send + 'call>>;

/// The future of [`ScheduleControl::run_now`]: the run was admitted, or the refusal.
pub type RunNow<'call> =
    Pin<Box<dyn Future<Output = Result<RunNowStarted, ScheduleRefusal>> + Send + 'call>>;

/// The running scheduler as the scheduled actions page uses it.
pub trait ScheduleControl: fmt::Debug + Send + Sync {
    /// Whether `role` may schedule `draft` and the action can run on its router now: the
    /// permissions, a registered client and an existing policy read from the router, or
    /// an eligible preset. `Ok` carries the preset's source router (`None` for the other
    /// actions and for a preset without one), which the page stores with the schedule.
    fn check<'call>(&'call self, role: &'call Role, draft: &'call ScheduleDraft) -> Checked<'call>;

    /// Starts schedule `id` now for `actor` (`web:<username>`), whose `role` must hold
    /// `ManageSchedules` and the action's permissions on the router, besides the owner's
    /// check every run makes. The run goes on in the background; a busy router does not
    /// refuse it: the run ends `Skipped router_busy` and is not retried.
    fn run_now<'call>(
        &'call self,
        role: &'call Role,
        actor: &'call str,
        id: &'call str,
    ) -> RunNow<'call>;

    /// The next slot of each router that has an active schedule: router id to the
    /// schedule's name and the slot in Unix seconds. Cheap, never waits.
    fn next_slots(&self) -> BTreeMap<String, (String, i64)>;
}

/// A schedule as the page's form built it, for [`ScheduleControl::check`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ScheduleDraft {
    /// Router profile id.
    pub router: String,
    /// What runs.
    pub action: Action,
}

impl ScheduleDraft {
    /// `action` on `router`.
    #[inline]
    #[must_use]
    pub const fn new(router: String, action: Action) -> Self {
        Self { router, action }
    }
}

/// The scheduler admitted a run-now; its result shows in the page's last-run column.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct RunNowStarted;

impl RunNowStarted {
    /// The run was admitted.
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

/// Why the scheduler refused a schedule or a run-now: a class only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ScheduleRefusal {
    /// The role lacks `ManageSchedules` or a permission the action needs.
    #[error("the role may not schedule this action")]
    Forbidden,
    /// The router could not be reached or read.
    #[error("the router could not be read")]
    Router,
    /// The client is not a registered client of the router.
    #[error("the client is not registered on the router")]
    ClientUnknown,
    /// The router has no policy of that name.
    #[error("the router has no such policy")]
    PolicyUnknown,
    /// The preset is missing or the role may not load it.
    #[error("the preset is not available")]
    PresetUnavailable,
    /// The router's firmware cannot take the preset.
    #[error("the router's firmware cannot take the preset")]
    Firmware,
    /// The router runs a documentation-based firmware line and it was not acknowledged.
    #[error("the documentation-based firmware line was not acknowledged")]
    DocumentationTier,
    /// The preset's plan needs input or has conflicts.
    #[error("the preset's plan is not ready")]
    NotReady,
    /// The preset changes how kcc manages the router.
    #[error("the preset holds management lines")]
    ManagementLines,
    /// The preset holds a WireGuard private key.
    #[error("the preset holds a WireGuard private key")]
    WireguardKey,
    /// The router is busy with another change (run-now only).
    #[error("the router is busy")]
    Busy,
    /// No scheduler runs in this process.
    #[error("no scheduler is running")]
    Unavailable,
}

impl ScheduleRefusal {
    /// Every refusal, in [`Self::code`] order of the documentation.
    const ALL: [Self; 12] = [
        Self::Forbidden,
        Self::Router,
        Self::ClientUnknown,
        Self::PolicyUnknown,
        Self::PresetUnavailable,
        Self::Firmware,
        Self::DocumentationTier,
        Self::NotReady,
        Self::ManagementLines,
        Self::WireguardKey,
        Self::Busy,
        Self::Unavailable,
    ];

    /// Stable snake-case code, as the audit log records it.
    #[inline]
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Forbidden => "forbidden",
            Self::Router => "router",
            Self::ClientUnknown => "client_unknown",
            Self::PolicyUnknown => "policy_unknown",
            Self::PresetUnavailable => "preset_unavailable",
            Self::Firmware => "firmware",
            Self::DocumentationTier => "documentation_tier",
            Self::NotReady => "not_ready",
            Self::ManagementLines => "management_lines",
            Self::WireguardKey => "wireguard_key",
            Self::Busy => "busy",
            Self::Unavailable => "unavailable",
        }
    }

    /// The refusal whose [`Self::code`] is `code`.
    #[inline]
    #[must_use]
    pub fn from_code(code: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|refusal| refusal.code() == code)
    }
}
