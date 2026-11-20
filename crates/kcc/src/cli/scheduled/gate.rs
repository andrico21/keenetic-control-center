//! What every change and run-now of a schedule passes first: the role, the router's
//! eligibility check (as the Web page makes it) and the confirmation of its risk.

use core::iter;

use kcc_app::{audit::Attempt, permissions::Permission, schedules::model::Action};
use kcc_catalog::Risk;
use kcc_i18n::keys;

use super::role;
use crate::{
    cli::{
        context::{Ctx, Services},
        exit::{Exit, Failure, Outcome, denied},
        secret::confirm,
    },
    server_schedules::{
        actions::ActionDeps,
        eligible::{Draft, ScheduleRefusal, check},
        lines::reason,
        preset::PresetRefusal,
        standalone,
    },
};

/// Checks that `action` on `router` could run with the CLI user's authority: the
/// permissions first (a refusal is audited), then the router.
///
/// Answers the actions of this process (for a run-now) and the preset's source router.
///
/// # Errors
///
/// Returns the policy refusal, a refusal of the check, or a job runner failure.
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned
// router session; a refusal audit may append after cancellation.
pub(super) async fn checked(
    ctx: &Ctx,
    services: &Services,
    (router, action): (&str, &Action),
) -> Outcome<(ActionDeps, Option<String>)> {
    let needed = iter::once(Permission::ManageSchedules)
        .chain(action.permissions().iter().copied())
        .collect::<Vec<_>>();
    drop(ctx.authorize_audited(services, &needed, &[router]).await?);
    let role = role(ctx)?;
    let actions = standalone::actions(services.core(), ctx.state())
        .await
        .map_err(|error| Failure::text(Exit::Generic, &error))?;
    match check(&actions, &role, &Draft::new(router, action)).await {
        Ok(source) => Ok((actions, source)),
        Err(refusal) => {
            let forbidden = matches!(
                refusal,
                ScheduleRefusal::Forbidden | ScheduleRefusal::Preset(PresetRefusal::Forbidden)
            );
            if forbidden {
                ctx.attempt(services, "cli.refused", Some(router), Attempt::Forbidden)
                    .await;
            }
            Err(refused(ctx, router, refusal))
        }
    }
}

/// Asks before a schedule of `action` on `router` is stored or run.
///
/// A reboot needs `--confirm-destructive <router>`, a policy switch or a preset `--yes` or
/// a terminal "yes", a backup nothing. A missing confirmation is audited.
///
/// # Errors
///
/// Returns the policy refusal (exit 10).
// NOT cancel-safe: the refusal audit may append after cancellation.
pub(super) async fn confirmed(
    ctx: &Ctx,
    services: &Services,
    (router, action): (&str, &Action),
) -> Outcome {
    let risk = match action {
        Action::Backup => Risk::Read,
        Action::Reboot => Risk::Destructive,
        Action::PolicySwitch { mac: _, policy: _ }
        | Action::Preset {
            preset_id: _,
            ack_documentation_tier: _,
        }
        | _ => Risk::Management,
    };
    let confirmation = confirm(ctx.out(), ctx.globals(), risk, router, false);
    ctx.confirmed(services, router, confirmation).await
}

/// The exit code of a run that ended with, or a check that refused with, `code`.
pub(super) fn exit_for(code: &str) -> Exit {
    match code {
        "forbidden" | "firmware" | "documentation_tier" => Exit::Policy,
        "router_busy" => Exit::Conflict,
        "client_unknown" | "policy_unknown" | "preset_unavailable" | "not_ready"
        | "management_lines" | "wireguard_key" => Exit::Validation,
        _ => Exit::Router,
    }
}

/// The failure of `refusal` on `router`.
fn refused(ctx: &Ctx, router: &str, refusal: ScheduleRefusal) -> Failure {
    match refusal {
        ScheduleRefusal::Forbidden | ScheduleRefusal::Preset(PresetRefusal::Forbidden) => {
            denied(router)
        }
        ScheduleRefusal::Router | ScheduleRefusal::Preset(PresetRefusal::Router) => {
            Failure::message(
                Exit::Router,
                keys::CLI_SCHEDULED_ROUTER_UNREADABLE,
                &[("router", router)],
            )
        }
        ScheduleRefusal::ClientUnknown
        | ScheduleRefusal::PolicyUnknown
        | ScheduleRefusal::Preset(
            PresetRefusal::Unavailable
            | PresetRefusal::Firmware
            | PresetRefusal::DocumentationTier
            | PresetRefusal::NotReady
            | PresetRefusal::ManagementLines
            | PresetRefusal::WireGuardKey,
        ) => Failure::message(
            exit_for(refusal.code()),
            keys::CLI_SCHEDULED_REFUSED,
            &[("reason", &reason(ctx.out().locale(), refusal.code()))],
        ),
    }
}
