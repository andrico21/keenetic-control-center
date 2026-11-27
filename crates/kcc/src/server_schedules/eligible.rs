//! Whether a schedule could run as drafted: the check the Web page and the CLI make
//! before they create, edit, resume or run a schedule now.
//!
//! It is the creation-time version of what a run checks: the role holds
//! `ManageSchedules` and every permission of the action on the router; a policy switch
//! names a registered client of the router and one of its policies; a preset plans as a
//! run would ([`preset::eligible`]). A backup or a reboot needs no router read.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "test code is not rendered API documentation"
)]
mod tests;

use kcc_app::{
    permissions::{Permission, Role},
    registry::{RouterRegistry, authorize},
    schedules::model::Action,
};
use kcc_catalog::Catalog;
use kcc_domain::{
    DomainError, RouterCtx,
    clients::{self, Client},
    policies::read::policies,
};

use super::{
    actions::ActionDeps,
    preset::{self, PresetRefusal, Target},
};

/// A schedule as a form or a command drafts it: the router and the action.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Draft<'draft> {
    /// The router profile id.
    router: &'draft str,
    /// What would run.
    action: &'draft Action,
}

impl<'draft> Draft<'draft> {
    /// `action` on `router`.
    pub(crate) const fn new(router: &'draft str, action: &'draft Action) -> Self {
        Self { router, action }
    }
}

/// Why a drafted schedule could not run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ScheduleRefusal {
    /// The role lacks `ManageSchedules` or a permission of the action on the router.
    Forbidden,
    /// The router could not be read.
    Router,
    /// The policy switch's client is not a registered client of the router.
    ClientUnknown,
    /// The router has no connection policy of the policy switch's name.
    PolicyUnknown,
    /// The preset may not run unattended.
    Preset(PresetRefusal),
}

impl ScheduleRefusal {
    /// The machine-read code; a run that meets the same refusal reports the same code.
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::Forbidden => "forbidden",
            Self::Router => "router",
            Self::ClientUnknown => "client_unknown",
            Self::PolicyUnknown => "policy_unknown",
            Self::Preset(refusal) => refusal.code(),
        }
    }
}

/// Checks that `draft` could run now with `role`.
///
/// On success it answers the preset's source router for a preset that names one, for
/// `NewSchedule::with_preset_source`; `None` for the other actions.
///
/// # Errors
///
/// Why the drafted schedule could not run.
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned
// router session. Apart from that, reads.
pub(crate) async fn check(
    deps: &ActionDeps,
    role: &Role,
    draft: &Draft<'_>,
) -> Result<Option<String>, ScheduleRefusal> {
    permitted(role, draft)?;
    match draft.action {
        Action::PolicySwitch { mac, policy } => {
            let router = context(deps.registry(), draft.router).await?;
            drop(registered(&router, (mac.as_str(), policy.as_str()), None).await?);
            Ok(None)
        }
        Action::Preset {
            preset_id,
            ack_documentation_tier,
        } => {
            let target = Target::new(draft.router, preset_id.as_str(), *ack_documentation_tier);
            preset::eligible(deps, role, target)
                .await
                .map_err(ScheduleRefusal::Preset)
        }
        Action::Backup | Action::Reboot => Ok(None),
        _ => Err(ScheduleRefusal::Forbidden),
    }
}

/// The registered client `mac` of `router`, when `router` also has the connection
/// policy `policy`: the rule a policy switch is checked by at creation and at run time.
///
/// # Errors
///
/// [`ScheduleRefusal::ClientUnknown`], [`ScheduleRefusal::PolicyUnknown`], or
/// [`ScheduleRefusal::Router`] for a failed read, logged with `schedule` when a run asks.
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned
// router session. Apart from that, reads.
pub(super) async fn registered(
    router: &RouterCtx,
    (mac, policy): (&str, &str),
    schedule: Option<&str>,
) -> Result<Client, ScheduleRefusal> {
    let unreadable = |error: DomainError| {
        tracing::warn!(
            target: super::TARGET,
            schedule,
            %error,
            "scheduled policy switch could not read the router"
        );
        ScheduleRefusal::Router
    };
    let client = clients::read_client(router, mac)
        .await
        .map_err(unreadable)?
        .filter(|client| client.registered == Some(true))
        .ok_or(ScheduleRefusal::ClientUnknown)?;
    let known = policies(router)
        .await
        .map_err(unreadable)?
        .iter()
        .any(|state| state.name.as_deref() == Some(policy));
    known
        .then_some(client)
        .ok_or(ScheduleRefusal::PolicyUnknown)
}

/// Requires `ManageSchedules` and every permission of `draft`'s action on its router.
///
/// # Errors
///
/// [`ScheduleRefusal::Forbidden`].
fn permitted(role: &Role, draft: &Draft<'_>) -> Result<(), ScheduleRefusal> {
    if !role.grants(Permission::ManageSchedules) {
        return Err(ScheduleRefusal::Forbidden);
    }
    draft
        .action
        .permissions()
        .iter()
        .try_for_each(|permission| authorize(role, *permission, draft.router))
        .map_err(|_denied| ScheduleRefusal::Forbidden)
}

/// The router context of `router` over the shared client, with the router's catalog.
///
/// # Errors
///
/// [`ScheduleRefusal::Router`] when the router cannot be reached or detected.
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned
// router session. Apart from that, reads.
async fn context(registry: &RouterRegistry, router: &str) -> Result<RouterCtx, ScheduleRefusal> {
    let client = registry
        .client(router)
        .await
        .map_err(|_error| ScheduleRefusal::Router)?;
    let info = registry
        .poll_info(router)
        .await
        .map_err(|_error| ScheduleRefusal::Router)?;
    let catalog = Catalog::for_router(&info).map_err(|_error| ScheduleRefusal::Router)?;
    Ok(RouterCtx::new(client, catalog))
}
