//! Router profile commands.

use kcc_app::{entware_ssh::state::forget, permissions::Permission, registry::ProfileSource};
use kcc_catalog::Risk;
use kcc_i18n::keys;
use serde_json::{Value, json};
use url::Url;

use super::{
    args_fleet::RouterCommand,
    context::{Ctx, Services},
    exit::{Exit, Failure, Outcome},
    fleet::identity,
    outbound, router_secrets,
    secret::confirm,
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
        RouterCommand::Add(args) => router_secrets::add(ctx, &services, args).await,
        RouterCommand::Edit(args) => router_secrets::edit(ctx, &services, args).await,
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
        .authorize_audited(services, &[Permission::ManageRouters], &[id])
        .await?;
    let confirmation = confirm(ctx.out(), ctx.globals(), Risk::Management, id, false);
    ctx.confirmed(services, id, confirmation).await?;
    services.registry().delete(&role, id).await?;
    services.credentials().remove(id)?;
    forget(ctx.state(), id).map_err(|error| Failure::text(Exit::Generic, &error))?;
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
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, reads only.
async fn test(ctx: &Ctx, services: &Services) -> Outcome {
    let id = ctx.router_id(services)?;
    drop(
        ctx.authorize_audited(services, &[Permission::Read], &[&id])
            .await?,
    );
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

/// Parses a router origin.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
pub(super) fn parse_url(text: &str) -> Outcome<Url> {
    Url::parse(text).map_err(|error| Failure::text(Exit::Usage, &error))
}

/// The stable name of a profile source.
const fn source_name(source: ProfileSource) -> &'static str {
    match source {
        ProfileSource::Config => "config",
        ProfileSource::State | _ => "state",
    }
}
