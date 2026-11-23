//! Packages over SSH: lists read within the page's bound, installs run as jobs and read
//! back, names outside the grammar refused, router values escaped.

use core::time::Duration;

use axum::http::StatusCode;
use kcc_i18n::keys;
use kcc_testkit::entware_ssh::{Config, DEFAULT_PASSWORD, Fault};
use tokio::time::timeout;

use super::rig::{LIMIT, Rig};
use crate::support::{
    outcome::TestResult,
    page::{en, en_with},
};

/// Todo 15: a package installed from the form runs as a job whose stream reports the
/// version read back; the installed list then shows it.
#[tokio::test]
async fn a_package_installed_from_the_form_is_read_back() -> TestResult {
    let rig = Rig::start(Config::default().installable("htop", "3.3.0")).await?;
    let _enrolled = rig.enrol(DEFAULT_PASSWORD).await?;
    let (_, panel) = rig.post("packages/install", &[("name", "htop")]).await?;
    assert!(
        panel.contains(&en(keys::WEB_SYSTEM_ENTWARE_SSH_JOB)),
        "{panel}"
    );
    let received = rig.followed(&panel).await?;
    let installed = en_with(
        keys::WEB_SYSTEM_ENTWARE_SSH_JOB_INSTALLED,
        &[("name", "htop"), ("value", "3.3.0")],
    );
    assert!(received.contains(&installed), "{received}");
    assert!(
        received.contains(&en(keys::WEB_EXPLORER_JOB_COMPLETED)),
        "{received}"
    );
    assert_eq!(
        rig.ssh().installed().get("htop").map(String::as_str),
        Some("3.3.0")
    );
    let (_, listed) = rig.post("packages/list", &[]).await?;
    assert!(listed.contains("<td class=\"mono\">htop</td>"), "{listed}");
    assert!(listed.contains("3.3.0"), "{listed}");
    let count = en_with(
        keys::WEB_SYSTEM_ENTWARE_SSH_PACKAGES_COUNT,
        &[("value", "1")],
    );
    assert!(listed.contains(&count), "{listed}");
    assert!(
        rig.fixture()
            .audited("web.entware_ssh_install", "started")?
    );
    assert!(rig.fixture().audited("entware.ssh.install", "success")?);
    let (_, removal) = rig.post("packages/remove", &[("name", "htop")]).await?;
    let removing = rig.followed(&removal).await?;
    let removed = en_with(
        keys::WEB_SYSTEM_ENTWARE_SSH_JOB_REMOVED,
        &[("name", "htop")],
    );
    assert!(removing.contains(&removed), "{removing}");
    assert!(!rig.ssh().installed().contains_key("htop"));
    Ok(())
}

/// Todo 15: a package name outside the grammar is refused in the page's words before any
/// command, and never shown back.
#[tokio::test]
async fn a_name_outside_the_grammar_is_refused() -> TestResult {
    let rig = Rig::start(Config::default()).await?;
    let _enrolled = rig.enrol(DEFAULT_PASSWORD).await?;
    for hostile in ["htop;reboot", "<b>x</b>", "-x", ""] {
        let commands = rig.counters().commands;
        let (_, body) = rig.post("packages/install", &[("name", hostile)]).await?;
        assert!(
            body.contains(&en(keys::WEB_SYSTEM_ENTWARE_SSH_NAME_RULE)),
            "{body}"
        );
        assert!(!body.contains("<b>x</b>"), "{body}");
        assert_eq!(rig.counters().commands, commands, "{hostile}: nothing sent");
    }
    assert!(
        rig.fixture()
            .audited("web.entware_ssh_install", "validation_failed")?
    );
    Ok(())
}

/// Todo 15: versions the router reports are escaped and stripped of control characters
/// in both lists.
#[tokio::test]
async fn router_versions_are_escaped_and_stripped() -> TestResult {
    let config = Config::default()
        .installed("evil", "<script>alert(1)</script>\u{1b}[31m\u{7}")
        .upgradable("evil", "<img/src=x>\u{1b}[0m");
    let rig = Rig::start(config).await?;
    let _enrolled = rig.enrol(DEFAULT_PASSWORD).await?;
    for list in ["packages/list", "packages/upgradable"] {
        let (_, body) = rig.post(list, &[]).await?;
        assert!(
            body.contains("<td class=\"mono\">evil</td>"),
            "{list}: {body}"
        );
        assert!(!body.contains("<script>"), "{list}: {body}");
        assert!(!body.contains("<img"), "{list}: {body}");
        assert!(!body.contains('\u{1b}'), "{list}: {body}");
        assert!(!body.contains('\u{7}'), "{list}: {body}");
    }
    let (_, listed) = rig.post("packages/list", &[]).await?;
    assert!(
        listed.contains("&#60;script&#62;alert(1)&#60;/script&#62;[31m"),
        "{listed}"
    );
    let (_, offered) = rig.post("packages/upgradable", &[]).await?;
    assert!(offered.contains("&#60;img/src=x&#62;[0m"), "{offered}");
    Ok(())
}

/// Todo 15: a running change bounds reads and refuses changes.
///
/// While an install holds the router's SSH session, the router identity check and a list
/// answer in the page's bound that the router is busy (not a bare request timeout), and
/// the local changes and a second job are refused as busy; the install then finishes.
#[tokio::test]
async fn a_running_change_bounds_reads_and_refuses_changes() -> TestResult {
    let config = Config::default().installable("htop", "3.3.0");
    let rig = Rig::start_with(config, Duration::from_secs(2)).await?;
    let _enrolled = rig.enrol(DEFAULT_PASSWORD).await?;
    rig.ssh().set_fault(Some(Fault::HoldMutations));
    let (_, panel) = rig.post("packages/install", &[("name", "htop")]).await?;
    timeout(LIMIT, rig.ssh().held(1)).await??;
    let identity = rig.post("probe?mode=bootstrap", &[]);
    let (status, checked) = timeout(Duration::from_secs(15), identity).await??;
    assert_eq!(status, StatusCode::OK, "{checked}");
    assert!(
        checked.contains(&en(keys::WEB_SYSTEM_ENTWARE_SSH_SLOW)),
        "{checked}"
    );
    assert!(rig.fixture().audited("web.entware_ssh_probe", "timeout")?);
    let (_, slow) = timeout(Duration::from_secs(20), rig.post("packages/list", &[])).await??;
    assert!(
        slow.contains(&en(keys::WEB_SYSTEM_ENTWARE_SSH_SLOW)),
        "{slow}"
    );
    assert!(
        rig.fixture()
            .audited("web.entware_ssh_packages_list", "timeout")?
    );
    for (tail, pairs) in [
        ("disable", &[][..]),
        ("enabled?on=false", &[][..]),
        ("port", &[("port", "2222")][..]),
        ("packages/update", &[][..]),
    ] {
        let (_, busy) = rig.post(tail, pairs).await?;
        assert!(
            busy.contains(&en(keys::WEB_SYSTEM_JOB_BUSY)),
            "{tail}: {busy}"
        );
    }
    assert!(rig.fixture().audited("web.entware_ssh_update", "busy")?);
    assert!(
        rig.page(rig.admin())
            .await?
            .contains("data-state=\"active\"")
    );
    rig.ssh().set_fault(None);
    rig.ssh().release().await;
    let received = rig.followed(&panel).await?;
    assert!(
        received.contains(&en(keys::WEB_EXPLORER_JOB_COMPLETED)),
        "{received}"
    );
    Ok(())
}
