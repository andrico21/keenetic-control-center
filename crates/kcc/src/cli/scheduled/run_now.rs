//! `kcc scheduled run-now`: one run in this process, through the server's run path.
//!
//! The run acts as the schedule's owner, as a server's run would; the CLI user needs
//! `ManageSchedules` and the action's permissions besides. It is recorded without a slot
//! and audited as `schedule.run` requested by `cli:<user>`. It sends no Telegram message,
//! and a busy router ends it at once (`router_busy`) instead of being tried again.

extern crate alloc;

use alloc::sync::Arc;
use core::time::Duration;

use kcc_app::{
    permissions::load_roles,
    role_source::RoleSource,
    schedules::{
        ledger::{RunOutcome, RunState, Trigger},
        model::Schedule,
    },
};
use kcc_i18n::keys;
use serde_json::json;

use super::{
    gate::{checked, confirmed, exit_for},
    owner, refused, role, store,
};
use crate::{
    cli::{
        context::Ctx,
        exit::{Exit, Failure, Outcome},
    },
    server_schedules::{
        lines::{pause_code, reason},
        owner::AccountLookup,
        run::{Report, run_once},
        standalone::{self, Owners},
    },
};

/// How long the audit entries of the run may take to be written before the process
/// ends.
const AUDIT_FLUSH: Duration = Duration::from_secs(10);

/// Runs schedule `id` once now and prints how it ended.
///
/// # Errors
///
/// Returns policy, check or confirmation failures before the run, and the failure of a
/// run that did not succeed (exit 5 for a busy router).
// NOT cancel-safe: dropped during the run, the router may be left mid-change and the run
// stays `started` in the ledger.
pub(super) async fn run(ctx: &Ctx, id: &str) -> Outcome {
    let schedule = store(ctx)
        .get(&role(ctx)?, id)
        .map_err(|error| refused(error, (id, "-")))?;
    let services = ctx.services().await?;
    let target = (schedule.router.as_str(), &schedule.action);
    let (actions, _source) = checked(ctx, &services, target).await?;
    confirmed(ctx, &services, target).await?;
    let accounts: Arc<dyn AccountLookup> = Arc::new(ctx.accounts(&services));
    let roles = RoleSource::new(load_roles(ctx.state())?);
    let owners = Owners::new(accounts, roles, ctx.config().cli.clone());
    let deps = standalone::run_deps(&actions, ctx.state(), owners);
    let requested_by = owner(ctx).to_string();
    let report = run_once(&deps, id, Trigger::Now { requested_by }).await;
    let _unwritten: usize = services.audit_log().flush(AUDIT_FLUSH).await;
    ended(ctx, &schedule, report)
}

/// Prints a succeeded run, or answers the failure of one that did not succeed.
///
/// # Errors
///
/// The run's failure.
fn ended(ctx: &Ctx, schedule: &Schedule, report: Report) -> Outcome {
    let out = ctx.out();
    let (name, router) = (schedule.name.as_str(), schedule.router.as_str());
    let not_done = |code: &str| {
        let exit = exit_for(code);
        match code {
            "router_busy" => {
                return Failure::message(exit, keys::CLI_SCHEDULED_BUSY, &[("router", router)]);
            }
            "router" => {
                let names = [("router", router), ("name", name)];
                return Failure::message(exit, keys::CLI_SCHEDULED_RUN_ROUTER, &names);
            }
            _ => {}
        }
        Failure::message(
            exit,
            keys::CLI_SCHEDULED_NOT_DONE,
            &[
                ("name", name),
                ("router", router),
                ("reason", &reason(out.locale(), code)),
            ],
        )
    };
    match report {
        Report::Finished(RunOutcome::Succeeded { unsaved, checksum }) => {
            let mut text = out.tr(
                keys::CLI_SCHEDULED_RAN,
                &[("name", name), ("router", router)],
            );
            if unsaved {
                text.push('\n');
                text.push_str(&out.tr(keys::CLI_SCHEDULED_UNSAVED, &[]));
            }
            let result = RunState::from(RunOutcome::Succeeded { unsaved, checksum });
            out.emit(
                &json!({ "id": schedule.id, "router": router, "result": result }),
                &text,
            )
        }
        Report::Finished(RunOutcome::Failed { code } | RunOutcome::Skipped { reason: code }) => {
            Err(not_done(&code))
        }
        Report::Paused(why) => Err(Failure::message(
            Exit::Policy,
            keys::CLI_SCHEDULED_PAUSED_INSTEAD,
            &[
                ("name", name),
                ("reason", &reason(out.locale(), pause_code(why))),
            ],
        )),
        Report::Finished(_) | Report::Dropped => Err(Failure::message(
            Exit::Generic,
            keys::CLI_SCHEDULED_DROPPED,
            &[("id", &schedule.id)],
        )),
    }
}
