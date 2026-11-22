//! Package listings, the list update and package changes with their read-back.

use kcc_app::workflow::WorkflowError;
use kcc_ssh::{
    command::EntwareCommand,
    error::SshError,
    grammar::PackageName,
    parse::{self, Package},
    session::Session,
};

use super::{PackageChange, Run, session};
use crate::{RouterCtx, entware::ssh::error::EntwareError};

/// A package change and its target.
pub(super) enum Change {
    /// `opkg install`: the package must be installed afterwards.
    Install(PackageName),
    /// `opkg remove`: the package must be installed before and absent afterwards.
    Remove(PackageName),
    /// `opkg upgrade`: the package must be installed before and carry the offered version
    /// afterwards.
    Upgrade(PackageName),
}

/// The installed (`upgradable` false) or upgradable listing.
///
/// # Errors
/// As [`super::packages_list`].
// NOT cancel-safe: the chroot read may sign in first.
pub(super) async fn listing(
    run: &mut Run<'_>,
    router: &RouterCtx,
    upgradable: bool,
) -> Result<Vec<Package>, EntwareError> {
    run.read()?;
    let session = session::open(run, router).await?;
    let listing = if upgradable {
        let output = run.exec(&session, &EntwareCommand::ListUpgradable).await?;
        parse::upgradable(&output)?
    } else {
        installed(run, &session).await?
    };
    drop(session);
    Ok(listing)
}

/// `opkg update` under the lease; a non-zero exit fails.
///
/// # Errors
/// As [`super::update`].
// NOT cancel-safe: dropped while the command runs, the router may finish the update.
pub(super) async fn update(run: &mut Run<'_>, router: &RouterCtx) -> Result<(), EntwareError> {
    let _lease = run.write()?;
    let session = session::open(run, router).await?;
    let output = run.exec(&session, &EntwareCommand::Update).await?;
    drop(session);
    if output.exit_status() != 0 {
        return Err(SshError::UnexpectedOutput.into());
    }
    Ok(())
}

/// Runs `change` under the lease between two installed listings of the same session; the
/// read-back, not the exit status, decides.
///
/// # Errors
/// As [`super::remove`].
// NOT cancel-safe: dropped while the command runs, the router may finish the change.
pub(super) async fn change(
    run: &mut Run<'_>,
    router: &RouterCtx,
    change: Change,
) -> Result<PackageChange, EntwareError> {
    let _lease = run.write()?;
    let (package, command) = match &change {
        Change::Install(name) => (name.clone(), EntwareCommand::Install(name.clone())),
        Change::Remove(name) => (name.clone(), EntwareCommand::Remove(name.clone())),
        Change::Upgrade(name) => (name.clone(), EntwareCommand::Upgrade(name.clone())),
    };
    run.facts.package = Some(package.as_str().to_owned());
    let session = session::open(run, router).await?;
    let before = version(&installed(run, &session).await?, &package);
    let expected = match change {
        Change::Remove(_) | Change::Upgrade(_) if before.is_none() => {
            return Err(EntwareError::PackageNotInstalled {
                package: package.as_str().to_owned(),
            });
        }
        Change::Install(_) | Change::Remove(_) => None,
        Change::Upgrade(_) => offered(run, &session, &package)
            .await?
            .or_else(|| before.clone()),
    };
    let _status = run.exec(&session, &command).await?;
    let after = version(&installed(run, &session).await?, &package);
    drop(session);
    let verified = match change {
        Change::Install(_) => after.is_some(),
        Change::Remove(_) => after.is_none(),
        Change::Upgrade(_) => after.is_some() && after == expected,
    };
    if !verified {
        return Err(WorkflowError::VerificationFailed {
            field: format!("package {}", package.as_str()),
        }
        .into());
    }
    Ok(PackageChange {
        package,
        before,
        after,
    })
}

/// The installed listing.
///
/// # Errors
/// The command's failure or a non-zero exit.
// NOT cancel-safe: a dropped read leaves only a read-only command behind.
async fn installed(run: &mut Run<'_>, session: &Session) -> Result<Vec<Package>, EntwareError> {
    let output = run.exec(session, &EntwareCommand::ListInstalled).await?;
    Ok(parse::installed(&output)?)
}

/// The version the upgradable listing offers for `package`, if any.
///
/// # Errors
/// The command's failure or a non-zero exit.
// NOT cancel-safe: a dropped read leaves only a read-only command behind.
async fn offered(
    run: &mut Run<'_>,
    session: &Session,
    package: &PackageName,
) -> Result<Option<String>, EntwareError> {
    let output = run.exec(session, &EntwareCommand::ListUpgradable).await?;
    Ok(parse::upgradable(&output)?
        .into_iter()
        .find(|listed| listed.name == *package)
        .and_then(|listed| listed.new_version))
}

/// The installed version of `package` in `listing`.
fn version(listing: &[Package], package: &PackageName) -> Option<String> {
    listing
        .iter()
        .find(|listed| listed.name == *package)
        .map(|listed| listed.version.clone())
}
