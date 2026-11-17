//! System and internet commands.

use kcc_app::permissions::Permission;
use kcc_catalog::Risk;
use kcc_domain::{internet, system};
use kcc_i18n::keys;
use serde_json::json;

use super::{
    args_domains::{InternetCommand, SystemCommand},
    change::{Gate, applied},
    context::Ctx,
    domains::Session,
    exit::{Exit, Failure, Outcome},
};

/// Runs a `system` command.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: changes may apply before cancellation.
pub(crate) async fn system(ctx: &Ctx, command: SystemCommand) -> Outcome {
    let permission = match command {
        SystemCommand::Version
        | SystemCommand::State
        | SystemCommand::Clock
        | SystemCommand::Ntp
        | SystemCommand::Mode => Permission::Read,
        SystemCommand::Reboot | SystemCommand::FactoryReset => Permission::Destructive,
        SystemCommand::SetHostname { value: _ }
        | SystemCommand::SetDomain { value: _ }
        | SystemCommand::SetDescription { value: _ }
        | SystemCommand::SetTimezone { value: _ }
        | SystemCommand::SetNtpServer { value: _ }
        | SystemCommand::NtpMaster { state: _ }
        | SystemCommand::NtpSyncPeriod { seconds: _ } => Permission::Write,
    };
    let session = Session::open(ctx, permission).await?;
    let router = session.router();
    let operation = match command {
        SystemCommand::Version => return session.show(&system::read_version(router).await?),
        SystemCommand::State => return session.show(&system::read_system(router).await?),
        SystemCommand::Clock => return session.show(&system::read_clock_date(router).await?),
        SystemCommand::Ntp => return session.show(&system::read_ntp_status(router).await?),
        SystemCommand::Mode => return session.show(&system::read_system_mode(router).await?),
        SystemCommand::Reboot => {
            let gate = Gate::new(Risk::Destructive, Permission::Destructive, false)
                .reporting(keys::CLI_DONE_TERMINAL);
            return session
                .change(gate, async |changes, context| {
                    drop(system::reboot(changes, context).await?);
                    Ok(json!({ "rebooting": true }))
                })
                .await;
        }
        SystemCommand::FactoryReset => {
            let gate = Gate::new(Risk::Destructive, Permission::Destructive, false)
                .reporting(keys::CLI_DONE_TERMINAL);
            let id = session.target().id().to_owned();
            return session
                .change(gate, async |changes, context| {
                    drop(
                        system::factory_reset(changes, context, &id, &id)
                            .await
                            .map_err(|error| Failure::text(Exit::Router, &error))?,
                    );
                    Ok(json!({ "factory_reset": true }))
                })
                .await;
        }
        SystemCommand::SetHostname { value } => system::plan_hostname(router, &value)?,
        SystemCommand::SetDomain { value } => system::plan_domainname(router, &value)?,
        SystemCommand::SetDescription { value } => system::plan_description(router, &value)?,
        SystemCommand::SetTimezone { value } => system::plan_timezone(router, &value)?,
        SystemCommand::SetNtpServer { value } => system::plan_ntp_server(router, &value)?,
        SystemCommand::NtpMaster { state } => system::plan_ntp_master(router, state.enabled())?,
        SystemCommand::NtpSyncPeriod { seconds } => system::plan_ntp_sync_period(router, seconds)?,
    };
    let request = system::change_request(&operation)?;
    session
        .change(Gate::of(&operation), async |changes, _context| {
            Ok(applied(changes.apply(request).await?.unsaved))
        })
        .await
}

/// Runs an `internet` command.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, reads only.
pub(crate) async fn internet(ctx: &Ctx, command: InternetCommand) -> Outcome {
    let session = Session::open(ctx, Permission::Read).await?;
    match command {
        InternetCommand::Status => session.show(&internet::read_status(session.router()).await?),
        InternetCommand::PingCheck => {
            session.show(&internet::read_ping_check(session.router()).await?)
        }
    }
}
