//! Web UI accounts, MCP API keys, first-run administration and the audit log.

use std::{
    io::{self, Write as _},
    path::Path,
};

use kcc_app::{
    accounts::{AccountChange, AccountError, Authentication, NewAccount},
    permissions::{Permission, assignment::GrantError},
};
use kcc_i18n::keys;
use rmcp_server_kit::auth::generate_api_key;
use secrecy::{ExposeSecret as _, SecretString};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use super::{
    args_admin::{AdminCommand, UserCommand},
    context::{Ctx, Services},
    dom_net::new_secret,
    exit::{Exit, Failure, Outcome, denied},
    secret::read_secret,
};

/// Runs a `user` command.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: changes write local state.
pub(crate) async fn user(ctx: &Ctx, command: UserCommand) -> Outcome {
    ctx.principal().require(Permission::ManageUsers)?;
    let services = ctx.services().await?;
    let accounts = ctx.accounts(&services);
    let out = ctx.out();
    match command {
        UserCommand::Add {
            username,
            role,
            locale,
        } => {
            let actor = ctx.principal().authority()?;
            let password = new_secret(ctx, &username)?;
            let new = NewAccount::new(username.clone(), password, role.clone()).with_locale(locale);
            match accounts.create(&actor, new) {
                Err(AccountError::Grant(GrantError::Forbidden)) => {
                    let params = json!({ "username": username, "role": role });
                    return Err(refused_grant(ctx, &services, "cli.user_add", params).await);
                }
                result => result?,
            }
            ctx.audit(
                &services,
                "cli.user_add",
                None,
                json!({ "username": username }),
                "success",
            )
            .await;
            out.emit(
                &json!({ "username": username, "added": true }),
                &out.tr(keys::CLI_USER_ADDED, &[("user", &username)]),
            )
        }
        UserCommand::Passwd {
            username,
            current_password_file,
        } => {
            let current = current_password_file.as_deref();
            passwd(ctx, &services, (&username, current)).await
        }
        UserCommand::List => {
            let list = accounts.list()?;
            let rows = list
                .iter()
                .map(|account| {
                    vec![
                        account.username.clone(),
                        account.role.clone(),
                        yes(ctx, account.disabled),
                    ]
                })
                .collect::<Vec<_>>();
            let document = json!({ "users": list.iter().map(|account| json!({ "username": account.username, "role": account.role, "locale": account.locale, "disabled": account.disabled })).collect::<Vec<_>>() });
            out.table(
                &document,
                &[
                    keys::CLI_COL_USER,
                    keys::CLI_COL_ROLE,
                    keys::CLI_COL_DISABLED,
                ],
                &rows,
            )
        }
        UserCommand::Disable { username, enable } => {
            let found = accounts.administer(&username, &AccountChange::Disabled(!enable))?;
            if found.is_none() {
                return Err(Failure::message(
                    Exit::Usage,
                    keys::CLI_NOT_FOUND,
                    &[("name", &username)],
                ));
            }
            ctx.audit(
                &services,
                "cli.user_disable",
                None,
                json!({ "username": username, "disabled": !enable }),
                "success",
            )
            .await;
            out.emit(
                &json!({ "username": username, "disabled": !enable }),
                &out.tr(
                    if enable {
                        keys::CLI_ACCOUNT_ENABLED
                    } else {
                        keys::CLI_ACCOUNT_DISABLED
                    },
                    &[("user", &username)],
                ),
            )
        }
    }
}

/// Changes a Web UI account password after checking the current one.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: the password change writes local state.
async fn passwd(
    ctx: &Ctx,
    services: &Services,
    (username, current_password_file): (&str, Option<&Path>),
) -> Outcome {
    let accounts = ctx.accounts(services);
    let out = ctx.out();
    let new = new_secret(ctx, username)?;
    let own_account = ctx.principal().account_name() == username;
    let changed = if own_account {
        let current = read_secret(
            current_password_file,
            &out.tr(keys::CLI_PROMPT_CURRENT_PASSWORD, &[("user", username)]),
        )?;
        matches!(
            accounts.change_password(username, &current, &new)?,
            Authentication::Authenticated { role: _, locale: _ }
        )
    } else {
        accounts.reset_password(
            (ctx.principal().account_name(), ctx.principal().role()),
            username,
            &new,
        )?
    };
    let outcome = if changed { "success" } else { "denied" };
    ctx.audit(
        services,
        if own_account {
            "cli.user_passwd"
        } else {
            "cli.user_password_reset"
        },
        None,
        json!({ "username": username }),
        outcome,
    )
    .await;
    if outcome == "denied" {
        return Err(Failure::message(
            Exit::Auth,
            keys::CLI_PASSWORD_REJECTED,
            &[],
        ));
    }
    out.emit(
        &json!({ "username": username, "changed": true }),
        &out.tr(keys::CLI_PASSWORD_CHANGED, &[("user", username)]),
    )
}

/// Runs an `admin` command.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: creates the account.
pub(crate) async fn admin(ctx: &Ctx, command: AdminCommand) -> Outcome {
    let AdminCommand::Init { username } = command;
    ctx.principal().require(Permission::ManageUsers)?;
    let services = ctx.services().await?;
    let accounts = ctx.accounts(&services);
    if accounts.has_admin()? {
        return Err(Failure::message(
            Exit::Conflict,
            keys::CLI_ADMIN_EXISTS,
            &[],
        ));
    }
    let (token, _hash) =
        generate_api_key().map_err(|error| Failure::text(Exit::Generic, &error))?;
    let password = SecretString::from(token);
    accounts.create(
        &ctx.principal().authority()?,
        NewAccount::new(username.clone(), password.clone(), "admin".to_owned())
            .with_must_change_password(true),
    )?;
    ctx.audit(
        &services,
        "cli.admin_init",
        None,
        json!({ "username": username }),
        "success",
    )
    .await;
    let out = ctx.out();
    let mut stdout = io::stdout().lock();
    if out.json() {
        let document = Zeroizing::new(
            json!({ "username": username, "password": password.expose_secret() }).to_string(),
        );
        writeln!(stdout, "{}", document.as_str())?;
    } else {
        writeln!(
            stdout,
            "{}",
            out.tr(keys::CLI_ADMIN_CREATED, &[("user", &username)])
        )?;
        writeln!(stdout, "{}", password.expose_secret())?;
    }
    stdout.flush()?;
    Ok(())
}

/// Audits the refused role grant `action` as `forbidden` and returns the policy refusal
/// (exit 10), as the Web answers a role the actor does not dominate.
// NOT cancel-safe: the writer may append after cancellation.
pub(crate) async fn refused_grant(
    ctx: &Ctx,
    services: &Services,
    action: &str,
    params: Value,
) -> Failure {
    ctx.audit(services, action, None, params, "forbidden").await;
    denied("-")
}

/// Localized yes or nothing.
fn yes(ctx: &Ctx, value: bool) -> String {
    if value {
        ctx.out().tr(keys::CLI_YES, &[])
    } else {
        String::new()
    }
}
