//! Router users, routes, policies, NAT, firewall, services, components, storage and
//! schedule commands.

use kcc_app::permissions::Permission;
use kcc_domain::{
    components::{self, QueueAction},
    configuration::SafetyNet,
    firewall, policies, router_users, schedules, services, storage,
};
use kcc_i18n::keys;
use secrecy::SecretString;

use super::{
    args_domains_net::{
        ComponentsCommand, FirewallCommand, PoliciesCommand, QueueChoice, RouterUsersCommand,
        SchedulesCommand, ServicesCommand, StorageCommand,
    },
    context::Ctx,
    domains::Session,
    exit::Outcome,
    secret::read_secret,
};

/// Runs a `router-users` command.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: changes may apply before cancellation.
pub(crate) async fn router_users(ctx: &Ctx, command: RouterUsersCommand) -> Outcome {
    let permission = if matches!(command, RouterUsersCommand::List) {
        Permission::Read
    } else {
        Permission::ManageUsers
    };
    let protected = match &command {
        RouterUsersCommand::Passwd { name } => Some(name.as_str()),
        RouterUsersCommand::List
        | RouterUsersCommand::Add { name: _, tags: _ }
        | RouterUsersCommand::Tag {
            name: _,
            tag: _,
            state: _,
        }
        | RouterUsersCommand::Delete { name: _ } => None,
    };
    let session = match protected {
        Some(account) => Session::open_for_account_password(ctx, permission, account).await?,
        None => Session::open(ctx, permission).await?,
    };
    let router = session.router();
    let operation = match command {
        RouterUsersCommand::List => return session.show(&router_users::read_users(router).await?),
        RouterUsersCommand::Add { name, tags } => {
            let borrowed = tags.iter().map(String::as_str).collect::<Vec<_>>();
            router_users::plan_create(router, &name, &borrowed)?
        }
        RouterUsersCommand::Tag { name, tag, state } => {
            router_users::plan_tag(router, &name, &tag, state.enabled())?
        }
        RouterUsersCommand::Passwd { name } => {
            let password = new_secret(ctx, &name)?;
            router_users::plan_password(router, &name, &session.profile_login()?, password)?
        }
        RouterUsersCommand::Delete { name } => {
            router_users::plan_delete(router, &name, &session.profile_login()?)?
        }
    };
    session
        .cli(&operation, router_users::change_request(&operation)?)
        .await
}

/// Runs a `policies` command.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// cancel-safe: reads only.
pub(crate) async fn policies(ctx: &Ctx, command: PoliciesCommand) -> Outcome {
    let PoliciesCommand::List = command;
    let session = Session::open(ctx, Permission::Read).await?;
    session.show(&policies::read::policies(session.router()).await?)
}

/// Runs a `firewall` command.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// cancel-safe: reads only.
pub(crate) async fn firewall(ctx: &Ctx, command: FirewallCommand) -> Outcome {
    let session = Session::open(ctx, Permission::Read).await?;
    match command {
        FirewallCommand::AccessLists => {
            session.show(&firewall::read::access_lists(session.router()).await?)
        }
        FirewallCommand::Upnp => {
            session.show(&firewall::read::upnp_redirects(session.router()).await?)
        }
    }
}

/// Runs a `services` command.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: changes may apply before cancellation.
pub(crate) async fn services(ctx: &Ctx, command: ServicesCommand) -> Outcome {
    match command {
        ServicesCommand::List => {
            let session = Session::open(ctx, Permission::Read).await?;
            session.show(&services::read_services(session.router()).await?)
        }
        ServicesCommand::Set { name, state } => {
            let permissions = SafetyNet::required(Permission::Write, services::service_risk(&name));
            let session = Session::open_permissions(ctx, &permissions).await?;
            let operation = services::plan_service(session.router(), &name, state.enabled())?;
            session
                .cli(&operation, services::change_request(&operation)?)
                .await
        }
    }
}

/// Runs a `components` command.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: changes may apply before cancellation.
pub(crate) async fn components(ctx: &Ctx, command: ComponentsCommand) -> Outcome {
    let permission = match command {
        ComponentsCommand::List | ComponentsCommand::Pending => Permission::Read,
        ComponentsCommand::CheckUpdate
        | ComponentsCommand::Queue {
            action: _,
            component: _,
        } => Permission::Write,
    };
    let session = Session::open(ctx, permission).await?;
    let router = session.router();
    let operation = match command {
        ComponentsCommand::List => {
            return session.show(&components::read_components(router).await?);
        }
        ComponentsCommand::Pending => {
            return session.show(&components::read_pending(router).await?);
        }
        ComponentsCommand::CheckUpdate => components::plan_check_update(router)?,
        ComponentsCommand::Queue { action, component } => {
            let staged = match action {
                QueueChoice::Install => QueueAction::Install,
                QueueChoice::Remove => QueueAction::Remove,
            };
            components::plan_queue(router, staged, &component)?
        }
    };
    session
        .cli(&operation, components::change_request(&operation)?)
        .await
}

/// Runs a `storage` command.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: changes may apply before cancellation.
pub(crate) async fn storage(ctx: &Ctx, command: StorageCommand) -> Outcome {
    match command {
        StorageCommand::Media => {
            let session = Session::open(ctx, Permission::Read).await?;
            session.show(&storage::read_media(session.router()).await?)
        }
        StorageCommand::Usb => {
            let session = Session::open(ctx, Permission::Read).await?;
            session.show(&storage::read_usb(session.router()).await?)
        }
        StorageCommand::Eject { media } => {
            let session = Session::open(ctx, Permission::Destructive).await?;
            let target = session.target();
            let operation =
                storage::plan_eject(session.router(), target.id(), target.role(), &media, true)?;
            session
                .cli(&operation, storage::change_request(&operation)?)
                .await
        }
    }
}

/// Runs a `schedules` command.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: changes may apply before cancellation.
pub(crate) async fn schedules(ctx: &Ctx, command: SchedulesCommand) -> Outcome {
    if matches!(command, SchedulesCommand::List) {
        let session = Session::open(ctx, Permission::Read).await?;
        return session.show(&schedules::read_schedules(session.router()).await?);
    }
    let session = Session::open(ctx, Permission::Write).await?;
    let operation = match command {
        SchedulesCommand::List => return Ok(()),
        SchedulesCommand::Create { name } => schedules::plan_create(session.router(), &name)?,
        SchedulesCommand::Describe { name, description } => {
            schedules::plan_description(session.router(), &name, &description)?
        }
    };
    session
        .cli(&operation, schedules::change_request(&operation)?)
        .await
}

/// Reads a new router secret for `name` from the usual sources.
///
/// # Errors
///
/// Returns a usage failure when no source is available.
pub(crate) fn new_secret(ctx: &Ctx, name: &str) -> Outcome<SecretString> {
    read_secret(
        ctx.globals().password_file(),
        &ctx.out()
            .tr(keys::CLI_PROMPT_NEW_PASSWORD, &[("user", name)]),
    )
}
