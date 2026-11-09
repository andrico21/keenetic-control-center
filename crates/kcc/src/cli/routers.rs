//! Router profile commands.

use std::path::{self, PathBuf};

use kcc_app::{
    permissions::Permission,
    registry::{ManagedRouterProfile, ProfileSource},
    settings::RouterTls,
};
use kcc_catalog::Risk;
use kcc_i18n::keys;
use serde_json::{Value, json};
use url::Url;

use super::{
    args_fleet::RouterCommand,
    context::{Ctx, Services},
    exit::{Exit, Failure, Outcome},
    fleet::identity,
    outbound,
    secret::{confirm, read_secret},
};

/// Runs a `router` command.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: adding, editing and removing write local state.
pub(crate) async fn router(ctx: &Ctx, command: RouterCommand) -> Outcome {
    let services = ctx.services().await?;
    match command {
        RouterCommand::List => list(ctx, &services),
        RouterCommand::Add {
            id,
            url: address,
            login,
            tags,
            test_device,
            pin_sha256,
        } => {
            let role = ctx
                .principal()
                .authorize(&[Permission::ManageRouters], &[&id])?;
            let url = parse_url(&address)?;
            outbound::check(services.registry(), &url).await?;
            let (password_file, password) = password(ctx, &services, &id)?;
            let mut profile = ManagedRouterProfile::new(id.clone(), url, login, password_file);
            profile.tags = tags;
            profile.test_device = test_device;
            profile.tls = pin_sha256.map_or(RouterTls::Verify, RouterTls::PinSha256);
            services.registry().create(&role, profile).await?;
            if let Some(secret) = password
                && let Err(error) = services.credentials().store(&id, &secret)
            {
                drop(services.registry().delete(&role, &id).await);
                return Err(error.into());
            }
            ctx.audit(
                &services,
                "cli.router_add",
                Some(&id),
                Value::Null,
                "success",
            )
            .await;
            let out = ctx.out();
            out.emit(
                &json!({ "id": id, "added": true }),
                &out.tr(keys::CLI_ROUTER_ADDED, &[("name", &id)]),
            )
        }
        RouterCommand::Edit {
            id,
            url,
            login,
            tags,
            test_device,
            pin_sha256,
            new_password,
        } => {
            let role = ctx
                .principal()
                .authorize(&[Permission::ManageRouters], &[&id])?;
            let mut profile = services.registry().get(&id)?.profile;
            if let Some(text) = url {
                profile.url = parse_url(&text)?;
            }
            if let Some(name) = login {
                profile.login = name;
            }
            if !tags.is_empty() {
                profile.tags = tags;
            }
            if let Some(flag) = test_device {
                profile.test_device = flag;
            }
            if let Some(pin) = pin_sha256 {
                profile.tls = RouterTls::PinSha256(pin);
            }
            if new_password {
                let (password_file, password) = password(ctx, &services, &id)?;
                profile.password_file = password_file;
                if let Some(secret) = password {
                    services.credentials().store(&id, &secret)?;
                }
            }
            services.registry().update(&role, profile).await?;
            ctx.audit(
                &services,
                "cli.router_edit",
                Some(&id),
                Value::Null,
                "success",
            )
            .await;
            let out = ctx.out();
            out.emit(
                &json!({ "id": id, "updated": true }),
                &out.tr(keys::CLI_ROUTER_UPDATED, &[("name", &id)]),
            )
        }
        RouterCommand::Remove { id } => remove(ctx, &services, &id).await,
        RouterCommand::Test => test(ctx, &services).await,
    }
}

/// Removes a router profile after confirmation.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: writes local state.
async fn remove(ctx: &Ctx, services: &Services, id: &str) -> Outcome {
    let role = ctx
        .principal()
        .authorize(&[Permission::ManageRouters], &[id])?;
    confirm(ctx.out(), ctx.globals(), Risk::Management, id, false)?;
    services.registry().delete(&role, id).await?;
    services.credentials().remove(id)?;
    ctx.audit(
        services,
        "cli.router_remove",
        Some(id),
        Value::Null,
        "success",
    )
    .await;
    let out = ctx.out();
    out.emit(
        &json!({ "id": id, "removed": true }),
        &out.tr(keys::CLI_ROUTER_REMOVED, &[("name", id)]),
    )
}

/// Logs in and detects the router without changing anything.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// cancel-safe: reads only.
async fn test(ctx: &Ctx, services: &Services) -> Outcome {
    let id = ctx.router_id(services)?;
    drop(ctx.principal().authorize(&[Permission::Read], &[&id])?);
    let profile = services.registry().get(&id)?.profile;
    let info = services
        .registry()
        .test_connection(&profile)
        .await
        .map_err(|error| outbound::explained(error, &profile.url))?;
    let out = ctx.out();
    let (model, firmware) = identity(&info);
    out.emit(
        &json!({ "id": id, "model": model, "firmware": firmware }),
        &out.tr(
            keys::CLI_CONNECTED,
            &[("model", &model), ("version", &firmware)],
        ),
    )
}

/// Lists the profiles in the principal's scope.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
fn list(ctx: &Ctx, services: &Services) -> Outcome {
    ctx.principal().require(Permission::Read)?;
    let entries = services
        .registry()
        .list()?
        .into_iter()
        .filter(|entry| ctx.principal().sees(&entry.profile.id))
        .collect::<Vec<_>>();
    let routers = entries
        .iter()
        .map(|entry| {
            json!({
                "id": entry.profile.id,
                "url": entry.profile.url.as_str(),
                "login": entry.profile.login,
                "tags": entry.profile.tags,
                "test_device": entry.profile.test_device,
                "source": source_name(entry.source),
            })
        })
        .collect::<Vec<_>>();
    let rows = entries
        .iter()
        .map(|entry| {
            vec![
                entry.profile.id.clone(),
                entry.profile.url.as_str().to_owned(),
                entry.profile.login.clone(),
                source_name(entry.source).to_owned(),
                entry.profile.tags.join(","),
            ]
        })
        .collect::<Vec<_>>();
    let out = ctx.out();
    let document = json!({ "routers": routers });
    if rows.is_empty() {
        return out.emit(&document, &out.tr(keys::CLI_NO_ROUTERS, &[]));
    }
    out.table(
        &document,
        &[
            keys::CLI_COL_ID,
            keys::CLI_COL_URL,
            keys::CLI_COL_LOGIN,
            keys::CLI_COL_SOURCE,
            keys::CLI_COL_TAGS,
        ],
        &rows,
    )
}

/// The password file of a profile: `--password-file` as given, else a secret from
/// `KCC_PASSWORD` or a prompt stored in `<state>/router-credentials/<id>.password`.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
fn password(
    ctx: &Ctx,
    services: &Services,
    id: &str,
) -> Outcome<(PathBuf, Option<secrecy::SecretString>)> {
    if let Some(path) = ctx.globals().password_file() {
        return Ok((path::absolute(path)?, None));
    }
    let secret = read_secret(
        None,
        &ctx.out()
            .tr(keys::CLI_PROMPT_ROUTER_PASSWORD, &[("router", id)]),
    )?;
    Ok((services.credentials().sealed_path(id)?, Some(secret)))
}

/// Parses a router origin.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
fn parse_url(text: &str) -> Outcome<Url> {
    Url::parse(text).map_err(|error| Failure::text(Exit::Usage, &error))
}

/// The stable name of a profile source.
const fn source_name(source: ProfileSource) -> &'static str {
    match source {
        ProfileSource::Config => "config",
        ProfileSource::State | _ => "state",
    }
}
