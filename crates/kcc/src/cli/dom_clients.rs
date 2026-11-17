//! Client commands: the client list, registrations, access and hotspot policies.

use kcc_app::permissions::Permission;
use kcc_domain::{
    DomainError,
    clients::{self, Access, Client, PolicySelection},
};
use kcc_i18n::keys;
use kcc_rci::Mac;
use serde_json::json;

use super::{
    args_dom_lan::{ClientsCommand, SelectionArgs},
    change::{Gate, applied},
    context::Ctx,
    domains::Session,
    exit::{Exit, Failure, Outcome},
};

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
        | ClientsCommand::Wake { mac: _ }
        | ClientsCommand::DefaultPolicy(_)
        | ClientsCommand::InterfacePolicy {
            interface: _,
            selection: _,
        } => Permission::Write,
    };
    let session = Session::open(ctx, permission).await?;
    let router = session.router();
    let operation = match command {
        ClientsCommand::List => return list_clients(&session).await,
        ClientsCommand::Show { mac } => return session.show(&known(&session, &mac).await?),
        ClientsCommand::Register { mac, name } => {
            clients::plan_register(router, typed_mac(&mac)?, &name)?
        }
        ClientsCommand::Remove { mac } => clients::plan_remove(router, &mac)?,
        ClientsCommand::Wake { mac } => clients::plan_wake(router, &mac)?,
        ClientsCommand::Access { mac, state } => {
            let client = known(&session, &mac).await?;
            let access = if state.enabled() {
                Access::Permit
            } else {
                Access::Deny
            };
            clients::plan_access(
                router,
                &client,
                &clients::registration_name(&client),
                access,
            )?
        }
        ClientsCommand::Schedule { mac, schedule } => {
            let client = known(&session, &mac).await?;
            clients::plan_schedule(
                router,
                &client,
                &clients::registration_name(&client),
                &schedule,
            )?
        }
        ClientsCommand::Policy { mac, policy } => {
            let client = known(&session, &mac).await?;
            clients::plan_policy(
                router,
                &client,
                &clients::registration_name(&client),
                &policy,
            )?
        }
        ClientsCommand::Priority { mac, priority } => {
            let client = known(&session, &mac).await?;
            clients::plan_priority(
                router,
                &client,
                &clients::registration_name(&client),
                priority,
            )?
        }
        ClientsCommand::DefaultPolicy(chosen) => {
            clients::plan_default_policy(router, selection(&chosen))?
        }
        ClientsCommand::InterfacePolicy {
            interface,
            selection: chosen,
        } => clients::plan_interface_policy(router, &interface, selection(&chosen))?,
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
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, reads only.
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
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, reads only.
async fn known(session: &Session<'_>, mac: &str) -> Outcome<Client> {
    clients::read_client(session.router(), mac)
        .await?
        .ok_or_else(|| Failure::message(Exit::Usage, keys::CLI_NOT_FOUND, &[("name", mac)]))
}

/// `mac` as a MAC address.
///
/// # Errors
///
/// Returns [`DomainError::InvalidCliToken`], like any value that is not one router CLI
/// word, when `mac` is not six colon-separated hexadecimal pairs.
pub(crate) fn typed_mac(mac: &str) -> Result<Mac, DomainError> {
    mac.parse().map_err(|_error| DomainError::InvalidCliToken)
}

/// The hotspot policy chosen on the command line.
fn selection(args: &SelectionArgs) -> PolicySelection<'_> {
    match (args.permit, args.policy.as_deref()) {
        (true, _) => PolicySelection::Access(Access::Permit),
        (false, Some(name)) => PolicySelection::Policy(name),
        (false, None) => PolicySelection::Access(Access::Deny),
    }
}
