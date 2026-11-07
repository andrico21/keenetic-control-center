//! System, internet, diagnostics, clients, DHCP and segment commands.

use kcc_app::permissions::Permission;
use kcc_catalog::Risk;
use kcc_domain::{
    clients::{self, Access, Client},
    dhcp, diagnostics, internet, segments, system,
};
use kcc_i18n::keys;
use serde_json::json;

use super::{
    args_domains::{
        ClientsCommand, DhcpCommand, DiagnosticsCommand, InternetCommand, SegmentsCommand,
        SystemCommand,
    },
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
            let gate = Gate::new(Risk::Destructive, Permission::Destructive, false);
            return session
                .change(gate, async |changes, context| {
                    drop(system::reboot(changes, context).await?);
                    Ok(json!({ "rebooting": true }))
                })
                .await;
        }
        SystemCommand::FactoryReset => {
            let gate = Gate::new(Risk::Destructive, Permission::Destructive, false);
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
// cancel-safe: reads only.
pub(crate) async fn internet(ctx: &Ctx, command: InternetCommand) -> Outcome {
    let session = Session::open(ctx, Permission::Read).await?;
    match command {
        InternetCommand::Status => session.show(&internet::read_status(session.router()).await?),
        InternetCommand::PingCheck => {
            session.show(&internet::read_ping_check(session.router()).await?)
        }
    }
}

/// Runs a `diagnostics` command.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// cancel-safe: reads only.
pub(crate) async fn diagnostics(ctx: &Ctx, command: DiagnosticsCommand) -> Outcome {
    let DiagnosticsCommand::Log { lines } = command;
    let session = Session::open(ctx, Permission::Read).await?;
    session.show(&diagnostics::read_log(&session.router().client, lines).await?)
}

/// Runs a `clients` command.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: changes may apply before cancellation.
pub(crate) async fn clients(ctx: &Ctx, command: ClientsCommand) -> Outcome {
    let permission = match command {
        ClientsCommand::List | ClientsCommand::Show { mac: _ } => Permission::Read,
        ClientsCommand::Register { mac: _, name: _ }
        | ClientsCommand::Remove { mac: _ }
        | ClientsCommand::Access { mac: _, state: _ }
        | ClientsCommand::Schedule {
            mac: _,
            schedule: _,
        }
        | ClientsCommand::Policy { mac: _, policy: _ }
        | ClientsCommand::Priority {
            mac: _,
            priority: _,
        }
        | ClientsCommand::Wake { mac: _ } => Permission::Write,
    };
    let session = Session::open(ctx, permission).await?;
    let router = session.router();
    let operation = match command {
        ClientsCommand::List => return list_clients(&session).await,
        ClientsCommand::Show { mac } => return session.show(&known(&session, &mac).await?),
        ClientsCommand::Register { mac, name } => clients::plan_register(router, &mac, &name)?,
        ClientsCommand::Remove { mac } => clients::plan_remove(router, &mac)?,
        ClientsCommand::Wake { mac } => clients::plan_wake(router, &mac)?,
        ClientsCommand::Access { mac, state } => {
            let client = known(&session, &mac).await?;
            let access = if state.enabled() {
                Access::Permit
            } else {
                Access::Deny
            };
            clients::plan_access(router, &client, &label(&client, &mac), access)?
        }
        ClientsCommand::Schedule { mac, schedule } => {
            let client = known(&session, &mac).await?;
            clients::plan_schedule(router, &client, &label(&client, &mac), &schedule)?
        }
        ClientsCommand::Policy { mac, policy } => {
            let client = known(&session, &mac).await?;
            clients::plan_policy(router, &client, &label(&client, &mac), &policy)?
        }
        ClientsCommand::Priority { mac, priority } => {
            let client = known(&session, &mac).await?;
            clients::plan_priority(router, &client, &label(&client, &mac), priority)?
        }
    };
    session
        .change(Gate::of(&operation), async |changes, context| {
            Ok(applied(
                clients::apply(changes, context, &operation).await?.unsaved,
            ))
        })
        .await
}

/// Prints the client table with localized headers.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// cancel-safe: reads only.
async fn list_clients(session: &Session<'_>) -> Outcome {
    let list = clients::read_clients(session.router()).await?;
    let cell = |value: Option<&String>| value.cloned().unwrap_or_default();
    let rows = list
        .iter()
        .map(|client| {
            vec![
                cell(client.mac.as_ref()),
                cell(client.ip.as_ref()),
                cell(client.name.as_ref()),
                cell(client.interface.as_ref()),
                cell(client.access.as_ref()),
            ]
        })
        .collect::<Vec<_>>();
    session.table(
        &json!({ "clients": list }),
        &[
            keys::CLI_COL_MAC,
            keys::CLI_COL_ADDRESS,
            keys::CLI_COL_NAME,
            keys::CLI_COL_INTERFACE,
            keys::CLI_COL_ACCESS,
        ],
        &rows,
    )
}

/// The client with `mac`, or a usage failure.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// cancel-safe: reads only.
async fn known(session: &Session<'_>, mac: &str) -> Outcome<Client> {
    clients::read_client(session.router(), mac)
        .await?
        .ok_or_else(|| Failure::message(Exit::Usage, keys::CLI_NOT_FOUND, &[("name", mac)]))
}

/// The name a client is registered under: its current name, else its MAC.
fn label(client: &Client, mac: &str) -> String {
    client.name.clone().unwrap_or_else(|| mac.to_owned())
}

/// Runs a `dhcp` command.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: changes may apply before cancellation.
pub(crate) async fn dhcp(ctx: &Ctx, command: DhcpCommand) -> Outcome {
    let permission = if matches!(command, DhcpCommand::StaticLease { mac: _, address: _ }) {
        Permission::Write
    } else {
        Permission::Read
    };
    let session = Session::open(ctx, permission).await?;
    let router = session.router();
    match command {
        DhcpCommand::Pools => session.show(&dhcp::read_pools(router).await?),
        DhcpCommand::Leases => session.show(&dhcp::read_static_leases(router).await?),
        DhcpCommand::Bindings => session.show(&dhcp::read_bindings(router).await?),
        DhcpCommand::Neighbours => session.show(&dhcp::read_neighbours(router).await?),
        DhcpCommand::StaticLease { mac, address } => {
            let operation = dhcp::plan_static_lease(router, &mac, address).await?;
            session
                .change(Gate::of(&operation), async |changes, context| {
                    Ok(applied(
                        dhcp::apply(changes, context, &operation).await?.unsaved,
                    ))
                })
                .await
        }
    }
}

/// Runs a `segments` command.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// cancel-safe: reads only.
pub(crate) async fn segments(ctx: &Ctx, command: SegmentsCommand) -> Outcome {
    let SegmentsCommand::List = command;
    let session = Session::open(ctx, Permission::Read).await?;
    session.show(&segments::read_segments(session.router()).await?)
}
