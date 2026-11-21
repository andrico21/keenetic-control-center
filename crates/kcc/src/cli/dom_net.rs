//! Router user and storage commands, and the new-secret prompt.

use kcc_app::permissions::Permission;
use kcc_domain::{entware, router_users, storage};
use kcc_i18n::keys;
use secrecy::SecretString;

use super::{
    args_domains_net::{RouterUsersCommand, StorageCommand},
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
        RouterUsersCommand::Passwd { name } | RouterUsersCommand::Delete { name } => {
            Some(name.as_str())
        }
        RouterUsersCommand::Tag {
            name,
            tag: _,
            state,
        } => (!state.enabled()).then_some(name.as_str()),
        RouterUsersCommand::List | RouterUsersCommand::Add { name: _, tags: _ } => None,
    };
    let session = match protected {
        Some(account) => Session::open_for_account(ctx, permission, account).await?,
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
            let own = session.profile_login()?;
            router_users::plan_tag(router, &name, &own, (&tag, state.enabled()))?
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
            let entware_media = entware::configured_media(session.router()).await?;
            let operation = storage::plan_eject(
                session.router(),
                target.id(),
                target.role(),
                &media,
                true,
                entware_media.as_deref(),
                false,
            )?;
            session
                .cli(&operation, storage::change_request(&operation)?)
                .await
        }
    }
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
