//! The guards of every SSH action: `Destructive` on the router before anything reaches the
//! router or the SSH server, the session's CSRF token, the router name typed, and chroot.

use axum::http::StatusCode;
use kcc_i18n::keys;
use kcc_testkit::entware_ssh::{Config, Counters, DEFAULT_PASSWORD, Service};

use super::rig::{Rig, SSH};
use crate::support::{
    outcome::TestResult,
    page::{en, en_with, text},
};

/// Every action of the SSH section: its path below the section, a valid form and its
/// audit action.
pub(crate) const ACTIONS: [(&str, &str, &str); 19] = [
    ("enabled?on=false", "", "web.entware_ssh_enabled"),
    ("port", "port=2222", "web.entware_ssh_port"),
    ("probe", "mode=bootstrap", "web.entware_ssh_probe"),
    ("bootstrap", STEP, "web.entware_ssh_bootstrap"),
    ("repin", STEP, "web.entware_ssh_repin"),
    ("revoke", "", "web.entware_ssh_revoke"),
    ("disable", "", "web.entware_ssh_disable"),
    ("packages/list", "", "web.entware_ssh_packages_list"),
    (
        "packages/upgradable",
        "",
        "web.entware_ssh_packages_upgradable",
    ),
    ("packages/update", "", "web.entware_ssh_update"),
    ("packages/install", "name=htop", "web.entware_ssh_install"),
    ("packages/remove", "name=htop", "web.entware_ssh_remove"),
    ("packages/upgrade", "name=htop", "web.entware_ssh_upgrade"),
    ("services/list", "", "web.entware_ssh_services_list"),
    ("services/status", SERVICE, "web.entware_ssh_service_status"),
    ("services/start", SERVICE, "web.entware_ssh_service_start"),
    ("services/stop", SERVICE, "web.entware_ssh_service_stop"),
    (
        "services/restart",
        SERVICE,
        "web.entware_ssh_service_restart",
    ),
    ("services/log", SERVICE, "web.entware_ssh_service_log"),
];

/// A well-formed second enrolment step.
const STEP: &str = "nonce=0000000000000000000000000000000000000000000000000000000000000000\
                    &fingerprint=SHA256:x&password=p&fingerprint_confirmed=yes&replace_active=yes";

/// A service the SSH fake has.
const SERVICE: &str = "name=S51dropbear";

/// What the confirmation of the action at `tail` says it does.
fn doing(tail: &str) -> &'static str {
    match tail {
        "probe" => "probe",
        "enabled?on=false" | "port" | "disable" => "local",
        "packages/list"
        | "packages/upgradable"
        | "services/list"
        | "services/status"
        | "services/log" => "read",
        _ => "change",
    }
}

/// What the SSH fake and the fake router saw so far.
fn seen(rig: &Rig) -> (Counters, u64) {
    (rig.counters(), rig.fixture().handle().request_count())
}

/// An enrolled rig with a package and a service.
async fn enrolled() -> TestResult<Rig> {
    let config = Config::default()
        .installed("htop", "3.2.0")
        .service("S51dropbear", Service::new("dropbear"));
    let rig = Rig::start(config).await?;
    let _enrolled = rig.enrol(DEFAULT_PASSWORD).await?;
    Ok(rig)
}

/// Todo 15: a viewer and an operator see no SSH section, and every SSH action they post
/// is refused with 403 and audited before the router or the SSH server hears anything.
#[tokio::test]
async fn roles_without_destructive_see_nothing_and_are_refused() -> TestResult {
    let rig = enrolled().await?;
    for role in ["viewer", "operator"] {
        let browser = rig.fixture().login(role).await?;
        let page = rig.page(&browser).await?;
        assert!(!page.contains("id=\"entware-ssh"), "{role}: {page}");
        for (tail, form, action) in ACTIONS {
            let before = seen(&rig);
            let confirmed = format!("{form}&confirm=yes&confirm_name=home");
            let response = rig
                .fixture()
                .post(&format!("{SSH}/{tail}"), &browser, &confirmed)
                .await?;
            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{role} {tail}");
            assert_eq!(seen(&rig), before, "{role} {tail}: nothing reached");
            assert!(rig.fixture().audited(action, "forbidden")?, "{role} {tail}");
        }
    }
    let admin = rig.page(rig.admin()).await?;
    assert!(admin.contains("id=\"entware-ssh\""), "{admin}");
    Ok(())
}

/// Todo 15: every SSH action without the session's CSRF token is refused before anything
/// is sent.
#[tokio::test]
async fn every_action_needs_the_session_token() -> TestResult {
    let rig = enrolled().await?;
    for (tail, form, _action) in ACTIONS {
        let before = seen(&rig);
        let confirmed = format!("{form}&confirm=yes&confirm_name=home");
        let response = rig
            .fixture()
            .post_without_token(&format!("{SSH}/{tail}"), rig.admin(), &confirmed)
            .await?;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{tail}");
        assert_eq!(seen(&rig), before, "{tail}: nothing reached");
    }
    Ok(())
}

/// Todo 15: every SSH action first asks for the router name, and nothing reaches the
/// router or the SSH server before it is typed.
#[tokio::test]
async fn every_action_asks_for_the_router_name() -> TestResult {
    let rig = enrolled().await?;
    for (tail, form, _action) in ACTIONS {
        let before = seen(&rig);
        let response = rig
            .fixture()
            .post(&format!("{SSH}/{tail}"), rig.admin(), form)
            .await?;
        let body = text(response).await?;
        let title = en_with(
            keys::WEB_SYSTEM_ENTWARE_SSH_CONFIRM_TITLE,
            &[("router", "home")],
        );
        assert!(body.contains(&title), "{tail}: {body}");
        let said = format!(
            "data-message-key=\"web-system-entware-ssh-confirm-{}\"",
            doing(tail)
        );
        assert!(body.contains(&said), "{tail}: {said} in {body}");
        let resent = match form {
            "" => format!("/ssh/{tail}\""),
            STEP => "hx-include=\"#entware-ssh-confirm-form\"".to_owned(),
            _ => format!("/ssh/{tail}?{form}\""),
        };
        assert!(body.contains(&resent), "{tail}: {resent} in {body}");
        assert!(!body.contains("password=p"), "{tail}: {body}");
        assert_eq!(seen(&rig), before, "{tail}: nothing reached");
    }
    Ok(())
}

/// Todo 15: with chroot on, the section says why SSH management stops and offers no
/// identity check, and a posted one is refused before any connection.
#[tokio::test]
async fn chroot_stops_the_ssh_actions() -> TestResult {
    let rig = Rig::start(Config::default()).await?;
    let page = rig.page(rig.admin()).await?;
    assert!(!page.contains("id=\"entware-ssh-chroot\""), "{page}");
    assert!(page.contains("id=\"entware-ssh-check\""), "{page}");
    assert!(rig.fixture().handle().configure("opkg chroot"));
    let chrooted = rig.page(rig.admin()).await?;
    assert!(chrooted.contains("id=\"entware-ssh-chroot\""), "{chrooted}");
    assert!(!chrooted.contains("id=\"entware-ssh-check\""), "{chrooted}");
    let (_, body) = rig.post("probe", &[("mode", "bootstrap")]).await?;
    assert!(
        body.contains(&en(keys::WEB_SYSTEM_ENTWARE_SSH_CHROOT)),
        "{body}"
    );
    assert_eq!(
        rig.counters().connections,
        0,
        "no connection while chroot is on"
    );
    Ok(())
}

/// Todo 15: SSH management switched off hides the identity check and the package and
/// service sections, and the domain refuses their actions; a port outside 1..65535 is
/// refused in the page's words.
#[tokio::test]
async fn switched_off_management_and_bad_ports_are_refused() -> TestResult {
    let rig = enrolled().await?;
    let (_, off) = rig.post("enabled?on=false", &[]).await?;
    assert!(
        off.contains(&en(keys::WEB_SYSTEM_ENTWARE_SSH_ENABLED_OFF)),
        "{off}"
    );
    let page = rig.page(rig.admin()).await?;
    assert!(!page.contains("id=\"entware-ssh-check\""), "{page}");
    assert!(
        !page.contains("id=\"entware-ssh-packages-panel\""),
        "{page}"
    );
    let commands = rig.counters().commands;
    let (_, refused) = rig.post("packages/list", &[]).await?;
    assert!(
        refused.contains(&en(keys::WEB_SYSTEM_ENTWARE_SSH_SWITCHED_OFF)),
        "{refused}"
    );
    assert_eq!(rig.counters().commands, commands, "nothing sent");
    let (_, on) = rig.post("enabled?on=true", &[]).await?;
    assert!(
        on.contains(&en(keys::WEB_SYSTEM_ENTWARE_SSH_ENABLED_ON)),
        "{on}"
    );
    assert!(
        rig.page(rig.admin())
            .await?
            .contains("id=\"entware-ssh-check\"")
    );
    assert!(
        rig.fixture()
            .audited("web.entware_ssh_enabled", "success")?
    );
    for port in ["0", "65536", "x"] {
        let (_, body) = rig.post("port", &[("port", port)]).await?;
        assert!(
            body.contains(&en(keys::WEB_SYSTEM_ENTWARE_SSH_PORT_RULE)),
            "{port}: {body}"
        );
    }
    assert!(
        rig.fixture()
            .audited("web.entware_ssh_port", "validation_failed")?
    );
    Ok(())
}
