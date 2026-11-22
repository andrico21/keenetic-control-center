//! Package listings, update, install, remove and upgrade with their read-back.

use kcc_app::workflow::WorkflowError;
use kcc_domain::entware::ssh::error::EntwareError;
use kcc_ssh::error::SshError;
use kcc_testkit::model::Firmware;

use crate::{
    harness::param,
    rig::{Done, Op, Rig, userland},
    support::{PROFILES, TestResult},
};

/// `(name, version, new version)` of a listing.
fn rows(done: Done) -> TestResult<Vec<(String, String, Option<String>)>> {
    let Done::Packages(packages) = done else {
        return Err(format!("not a listing: {done:?}").into());
    };
    Ok(packages
        .into_iter()
        .map(|package| {
            (
                package.name.as_str().to_owned(),
                package.version,
                package.new_version,
            )
        })
        .collect())
}

/// `(name, version, new version)` of one row.
fn row(name: &str, version: &str, new: Option<&str>) -> (String, String, Option<String>) {
    (name.to_owned(), version.to_owned(), new.map(str::to_owned))
}

/// Todo 11: the installed and upgradable listings are parsed into names and versions on
/// every firmware profile.
#[tokio::test]
async fn the_listings_are_parsed() -> TestResult {
    for firmware in PROFILES {
        let rig = Rig::with(firmware, userland()).await?;
        assert_eq!(
            rows(rig.ok(Op::List).await?)?,
            vec![
                row("dropbear", "2022.83-1", None),
                row("nano", "7.2-1", None),
                row("pinned", "1.0-1", None),
            ],
            "{firmware:?}"
        );
        assert_eq!(
            rows(rig.ok(Op::Upgradable).await?)?,
            vec![
                row("nano", "7.2-1", Some("7.4-1")),
                row("pinned", "1.0-1", Some("1.1-1")),
            ],
            "{firmware:?}"
        );
    }
    Ok(())
}

/// Todo 11: `update` runs one command and succeeds.
#[tokio::test]
async fn update_runs_one_command() -> TestResult {
    let rig = Rig::start().await?;
    let before = rig.commands()?;
    assert!(matches!(rig.ok(Op::Update).await?, Done::Updated));
    assert_eq!(rig.commands()? - before, 1);
    Ok(())
}

/// Todo 11: an `opkg update` that exits non-zero fails and is audited as an SSH failure.
#[tokio::test]
async fn a_failed_update_fails() -> TestResult {
    let rig = Rig::with(Firmware::V5_1, userland().update_fails()).await?;
    let outcome = rig.run(Op::Update).await?;
    assert!(
        matches!(outcome, Err(EntwareError::Ssh(SshError::UnexpectedOutput))),
        "{outcome:?}"
    );
    let entries = rig.harness().audited("entware.ssh.update")?;
    let entry = entries.first().ok_or("no update entry")?;
    assert_eq!(
        (entry.outcome.as_str(), param(entry, "error")),
        ("failed", "ssh".into())
    );
    Ok(())
}

/// Todo 11: an install is read back from the installed listing of the same session: one
/// connection, one sign-in.
#[tokio::test]
async fn install_reads_the_package_back() -> TestResult {
    let rig = Rig::start().await?;
    let counters = rig.harness().counters()?;
    let change = rig.change(Op::Install("htop")).await?;
    assert_eq!(rig.logins_since(counters)?, (1, 1, 0), "one session");
    assert_eq!(change.package.as_str(), "htop");
    assert_eq!(change.before, None);
    assert_eq!(change.after.as_deref(), Some("3.3.0-1"));
    let installed = rig.harness().ssh()?.installed();
    assert_eq!(installed.get("htop").map(String::as_str), Some("3.3.0-1"));
    let entries = rig.harness().audited("entware.ssh.install")?;
    let entry = entries.first().ok_or("no install entry")?;
    assert_eq!(entry.outcome, "success");
    assert_eq!(param(entry, "package"), "htop");
    Ok(())
}

/// Todo 11: an install that reports success but leaves the package absent (and one the
/// feed does not know) fails the read-back, naming the package.
#[tokio::test]
async fn an_install_that_did_not_happen_fails_the_read_back() -> TestResult {
    let rig = Rig::start().await?;
    for name in ["ghost", "absent"] {
        let outcome = rig.run(Op::Install(name)).await?;
        let expected = format!("package {name}");
        assert!(
            matches!(
                &outcome,
                Err(EntwareError::Workflow(WorkflowError::VerificationFailed { field }))
                    if *field == expected
            ),
            "{name}: {outcome:?}"
        );
    }
    let entries = rig.harness().audited("entware.ssh.install")?;
    let entry = entries.first().ok_or("no install entry")?;
    assert_eq!(entry.outcome, "failed");
    assert_eq!(param(entry, "error"), "verification");
    Ok(())
}

/// Todo 11: remove and upgrade of a package missing from the installed listing are
/// refused after that one listing, with no mutating command, in one session.
#[tokio::test]
async fn remove_or_upgrade_of_an_absent_package_sends_no_mutation() -> TestResult {
    let rig = Rig::start().await?;
    for op in [Op::Remove("htop"), Op::Upgrade("htop")] {
        let (before, counters) = (rig.commands()?, rig.harness().counters()?);
        let outcome = rig.run(op).await?;
        assert_eq!(
            rig.logins_since(counters)?,
            (1, 1, 0),
            "{op:?}: one session"
        );
        assert!(
            matches!(&outcome, Err(EntwareError::PackageNotInstalled { package }) if package == "htop"),
            "{op:?}: {outcome:?}"
        );
        assert_eq!(rig.commands()? - before, 1, "{op:?}: only the listing ran");
    }
    assert_eq!(rig.harness().ssh()?.installed().get("htop"), None);
    let entries = rig.harness().audited("entware.ssh.remove")?;
    let entry = entries.first().ok_or("no remove entry")?;
    assert_eq!(entry.outcome, "refused");
    assert_eq!(param(entry, "reason"), "package_not_installed");
    Ok(())
}

/// Todo 11: a removal is read back as absent; one that reports success while the package
/// stays fails the read-back.
#[tokio::test]
async fn remove_reads_the_absence_back() -> TestResult {
    let rig = Rig::start().await?;
    let change = rig.change(Op::Remove("dropbear")).await?;
    assert_eq!(
        (change.before.as_deref(), change.after.as_deref()),
        (Some("2022.83-1"), None)
    );
    assert_eq!(rig.harness().ssh()?.installed().get("dropbear"), None);
    let outcome = rig.run(Op::Remove("pinned")).await?;
    assert!(
        matches!(
            &outcome,
            Err(EntwareError::Workflow(WorkflowError::VerificationFailed { field }))
                if field == "package pinned"
        ),
        "{outcome:?}"
    );
    Ok(())
}

/// Todo 11: an upgrade is read back with the version the upgradable listing offered;
/// an upgrade that leaves the old version fails; a package without an upgrade keeps its
/// version and succeeds.
#[tokio::test]
async fn upgrade_reads_the_new_version_back() -> TestResult {
    let rig = Rig::start().await?;
    let change = rig.change(Op::Upgrade("nano")).await?;
    assert_eq!(
        (change.before.as_deref(), change.after.as_deref()),
        (Some("7.2-1"), Some("7.4-1"))
    );
    let outcome = rig.run(Op::Upgrade("pinned")).await?;
    assert!(
        matches!(
            &outcome,
            Err(EntwareError::Workflow(WorkflowError::VerificationFailed { field }))
                if field == "package pinned"
        ),
        "{outcome:?}"
    );
    let current = rig.change(Op::Upgrade("dropbear")).await?;
    assert_eq!(
        (current.before.as_deref(), current.after.as_deref()),
        (Some("2022.83-1"), Some("2022.83-1"))
    );
    Ok(())
}
