//! `kcc entware packages`: the installed and upgradable packages, the list update and the
//! read-back changes.

use kcc_domain::entware::ssh::ops::{self, PackageChange};
use kcc_i18n::keys;
use kcc_ssh::{grammar::PackageName, parse::Package};
use serde_json::{Value, json};

use super::{
    args_dom_entware_ssh::PackagesCommand,
    context::Ctx,
    dom_entware_ssh_gate::{clean, invalid_name, open},
    entry::Boxed,
    exit::Outcome,
};

/// A package change.
#[derive(Debug, Clone, Copy)]
enum Verb {
    /// `opkg install`.
    Install,
    /// `opkg remove`.
    Remove,
    /// `opkg upgrade`.
    Upgrade,
}

/// Runs an `entware packages` command.
///
/// The returned future fails with the command's failure and its exit code; see [`Boxed`]
/// for why it is boxed.
// NOT cancel-safe: changes may run on the router after cancellation.
pub(crate) fn packages(ctx: &Ctx, command: PackagesCommand) -> Boxed<'_> {
    match command {
        PackagesCommand::List => Box::pin(listing(ctx, false)),
        PackagesCommand::Upgradable => Box::pin(listing(ctx, true)),
        PackagesCommand::Update => Box::pin(update(ctx)),
        PackagesCommand::Install { name } => Box::pin(change(ctx, name, Verb::Install)),
        PackagesCommand::Remove { name } => Box::pin(change(ctx, name, Verb::Remove)),
        PackagesCommand::Upgrade { name } => Box::pin(change(ctx, name, Verb::Upgrade)),
    }
}

/// Prints the installed packages, or with `upgradable` those that have an upgrade.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: the router read may sign in first.
async fn listing(ctx: &Ctx, upgradable: bool) -> Outcome {
    let opened = open(ctx).await?;
    let target = opened.target(ctx).await?;
    let (ssh, caller, out) = (opened.ssh(), opened.caller(), ctx.out());
    let router = target.router();
    let packages = if upgradable {
        opened
            .read(out, ops::packages_upgradable(&ssh, router, &caller))
            .await?
    } else {
        opened
            .read(out, ops::packages_list(&ssh, router, &caller))
            .await?
    };
    let document = json!({ "packages": packages.iter().map(package_value).collect::<Vec<_>>() });
    if packages.is_empty() {
        return out.emit(&document, &out.tr(keys::CLI_ENTWARE_PACKAGES_NONE, &[]));
    }
    let rows = packages
        .iter()
        .map(|package| {
            let mut row = vec![clean(package.name.as_str()), clean(&package.version)];
            if upgradable {
                row.push(package.new_version.as_deref().map_or_default(clean));
            }
            row
        })
        .collect::<Vec<_>>();
    let headers = if upgradable {
        &[
            keys::CLI_COL_NAME,
            keys::CLI_COL_VERSION,
            keys::CLI_COL_UPGRADE,
        ][..]
    } else {
        &[keys::CLI_COL_NAME, keys::CLI_COL_VERSION][..]
    };
    out.table(&document, headers, &rows)
}

/// Updates the package lists.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: the router may finish the update after cancellation.
async fn update(ctx: &Ctx) -> Outcome {
    let opened = open(ctx).await?;
    let target = opened.target(ctx).await?;
    let out = ctx.out();
    ops::update(&opened.ssh(), target.router(), &opened.caller())
        .await
        .map_err(|error| opened.failure(out, error))?;
    out.emit(
        &json!({ "router": opened.id(), "updated": true }),
        &out.tr(
            keys::CLI_ENTWARE_PACKAGES_UPDATED,
            &[("router", opened.id())],
        ),
    )
}

/// Runs `verb` on the package `name` and prints the read-back versions.
///
/// # Errors
///
/// Returns the validation failure (exit 4) of a name outside the grammar before anything
/// else, or the command's failure with its exit code.
// NOT cancel-safe: the router may finish the change after cancellation.
async fn change(ctx: &Ctx, name: String, verb: Verb) -> Outcome {
    let package = PackageName::parse(&name).map_err(|_invalid| invalid_name())?;
    let opened = open(ctx).await?;
    let target = opened.target(ctx).await?;
    let (ssh, caller, out) = (opened.ssh(), opened.caller(), ctx.out());
    let router = target.router();
    let changed = match verb {
        Verb::Install => ops::install(&ssh, router, &caller, package).await,
        Verb::Remove => ops::remove(&ssh, router, &caller, package).await,
        Verb::Upgrade => ops::upgrade(&ssh, router, &caller, package).await,
    }
    .map_err(|error| opened.failure(out, error))?;
    let absent = out.tr(keys::CLI_ENTWARE_PACKAGE_ABSENT, &[]);
    let version =
        |installed: &Option<String>| installed.as_deref().map_or_else(|| absent.clone(), clean);
    let shown = clean(changed.package.as_str());
    out.emit(
        &change_value(&changed),
        &out.tr(
            keys::CLI_ENTWARE_PACKAGE_CHANGED,
            &[
                ("name", &shown),
                ("router", opened.id()),
                ("value", &version(&changed.after)),
                ("item", &version(&changed.before)),
            ],
        ),
    )
}

/// One package as JSON, its text cleaned.
fn package_value(package: &Package) -> Value {
    json!({
        "name": clean(package.name.as_str()),
        "version": clean(&package.version),
        "new_version": package.new_version.as_deref().map(clean),
    })
}

/// A read-back change as JSON, its text cleaned.
fn change_value(change: &PackageChange) -> Value {
    json!({
        "package": clean(change.package.as_str()),
        "before": change.before.as_deref().map(clean),
        "after": change.after.as_deref().map(clean),
    })
}
