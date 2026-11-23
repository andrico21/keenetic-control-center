//! The enrolment's life after its first steps: Pending after a wrong password, a changed
//! host key pinned again, kcc's key revoked on the router or forgotten here.

use kcc_i18n::keys;
use kcc_testkit::entware_ssh::{Config, DEFAULT_PASSWORD};

use super::rig::{Rig, marker};
use crate::support::{outcome::TestResult, page::en};

/// Todo 15: a wrong password leaves the enrolment Pending, without the package and service
/// sections; the host key changed by a reinstall is pinned again through the same two
/// steps.
#[tokio::test]
async fn pending_and_repin() -> TestResult {
    let rig = Rig::start(Config::default()).await?;
    let ticket = rig.probe("bootstrap").await?;
    let (_, body) = rig.confirm(("bootstrap", &ticket), &marker(), &[]).await?;
    assert!(
        body.contains(&en(keys::WEB_SYSTEM_ENTWARE_SSH_AUTH_REJECTED)),
        "{body}"
    );
    let page = rig.page(rig.admin()).await?;
    assert!(page.contains("data-state=\"pending\""), "{page}");
    assert!(
        !page.contains("id=\"entware-ssh-packages-panel\""),
        "{page}"
    );
    assert!(
        !page.contains("id=\"entware-ssh-services-panel\""),
        "{page}"
    );
    let _enrolled = rig.enrol(DEFAULT_PASSWORD).await?;
    let _new = rig.ssh().replace_host_key();
    let changed = rig.probe("repin").await?;
    assert_eq!(changed.fingerprint(), rig.fingerprint()?);
    let (_, repinned) = rig
        .confirm(
            ("repin", &changed),
            DEFAULT_PASSWORD,
            &[("replace_active", "yes")],
        )
        .await?;
    assert!(
        repinned.contains(&en(keys::WEB_SYSTEM_ENTWARE_SSH_REPINNED)),
        "{repinned}"
    );
    assert!(rig.page(rig.admin()).await?.contains(&rig.fingerprint()?));
    Ok(())
}

/// Todo 15: revoke removes kcc's key line from the router and forgets the enrolment;
/// forget here forgets it locally and leaves the line on the router.
#[tokio::test]
async fn revoke_and_forget() -> TestResult {
    let rig = Rig::start(Config::default()).await?;
    let _enrolled = rig.enrol(DEFAULT_PASSWORD).await?;
    let (_, revoked) = rig.post("revoke", &[]).await?;
    assert!(
        revoked.contains(&en(keys::WEB_SYSTEM_ENTWARE_SSH_REVOKED)),
        "{revoked}"
    );
    assert!(!rig.ssh().authorized_keys().contains(" kcc:home"));
    assert!(rig.page(rig.admin()).await?.contains("data-state=\"none\""));
    let port = rig.ssh_port();
    let (_, _set) = rig.post("port", &[("port", &port)]).await?;
    let _again = rig.enrol(DEFAULT_PASSWORD).await?;
    let (_, forgotten) = rig.post("disable", &[]).await?;
    assert!(
        forgotten.contains(&en(keys::WEB_SYSTEM_ENTWARE_SSH_DISABLED)),
        "{forgotten}"
    );
    assert!(
        rig.ssh().authorized_keys().contains(" kcc:home"),
        "left on the router"
    );
    assert!(rig.page(rig.admin()).await?.contains("data-state=\"none\""));
    assert!(rig.fixture().audited("entware.ssh.revoke", "success")?);
    assert!(rig.fixture().audited("entware.ssh.disable", "success")?);
    Ok(())
}
