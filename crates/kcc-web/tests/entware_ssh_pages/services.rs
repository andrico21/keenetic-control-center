//! Services over SSH: start, stop and restart run as jobs read back with `check`, status
//! and the masked log read within the page's bound, and a changed host key refused with
//! both fingerprints shown.

use kcc_i18n::keys;
use kcc_testkit::{
    entware_install::record,
    entware_ssh::{Config, DEFAULT_PASSWORD, Service},
};

use super::rig::Rig;
use crate::support::{
    outcome::TestResult,
    page::{en, en_with},
};

/// The service of the rig.
const DROPBEAR: &str = "S51dropbear";

/// An enrolled rig with a stopped dropbear.
async fn enrolled() -> TestResult<Rig> {
    let rig = Rig::start(Config::default().service(DROPBEAR, Service::new("dropbear"))).await?;
    let _enrolled = rig.enrol(DEFAULT_PASSWORD).await?;
    Ok(rig)
}

/// Whether the fake's dropbear runs.
fn running(rig: &Rig) -> bool {
    rig.ssh()
        .service(DROPBEAR)
        .is_some_and(|service| service.is_running())
}

/// Todo 15: the list names the service; start, stop and restart run as jobs whose stream
/// reports the state read back; status reads it; an unknown or malformed name is refused.
#[tokio::test]
async fn service_actions_are_read_back() -> TestResult {
    let rig = enrolled().await?;
    let (_, listed) = rig.post("services/list", &[]).await?;
    assert!(listed.contains(DROPBEAR), "{listed}");
    let count = en_with(
        keys::WEB_SYSTEM_ENTWARE_SSH_SERVICES_COUNT,
        &[("value", "1")],
    );
    assert!(listed.contains(&count), "{listed}");
    let said = |key| en_with(key, &[("name", DROPBEAR)]);
    for (verb, state, runs) in [
        ("start", keys::WEB_SYSTEM_ENTWARE_SSH_RUNNING, true),
        ("stop", keys::WEB_SYSTEM_ENTWARE_SSH_STOPPED, false),
        ("restart", keys::WEB_SYSTEM_ENTWARE_SSH_RUNNING, true),
    ] {
        let (_, panel) = rig
            .post(&format!("services/{verb}"), &[("name", DROPBEAR)])
            .await?;
        let received = rig.followed(&panel).await?;
        assert!(received.contains(&said(state)), "{verb}: {received}");
        assert_eq!(running(&rig), runs, "{verb}");
        let (_, status) = rig.post("services/status", &[("name", DROPBEAR)]).await?;
        assert!(status.contains(&said(state)), "{verb}: {status}");
    }
    let (_, unknown) = rig
        .post("services/status", &[("name", "S99nothing")])
        .await?;
    let missing = en_with(
        keys::WEB_SYSTEM_ENTWARE_SSH_SERVICE_UNKNOWN,
        &[("name", "S99nothing")],
    );
    assert!(unknown.contains(&missing), "{unknown}");
    let commands = rig.counters().commands;
    let (_, malformed) = rig
        .post("services/start", &[("name", "dropbear;x")])
        .await?;
    assert!(malformed.contains(&en(keys::WEB_SYSTEM_ENTWARE_SSH_SERVICE_RULE)));
    assert_eq!(rig.counters().commands, commands, "nothing sent");
    assert!(
        rig.fixture()
            .audited("entware.ssh.service_start", "success")?
    );
    Ok(())
}

/// Todo 15: the service log is escaped and honest about an unreadable log.
///
/// It shows the service's records escaped and stripped of control characters, without
/// other processes' records; a log the router answers as text is said to be empty or
/// unreadable, not merely empty.
#[tokio::test]
async fn the_service_log_is_escaped_and_honest() -> TestResult {
    let rig = enrolled().await?;
    let (_, empty) = rig.post("services/log", &[("name", DROPBEAR)]).await?;
    assert!(
        empty.contains(&en(keys::WEB_SYSTEM_ENTWARE_SSH_LOG_EMPTY)),
        "{empty}"
    );
    let handle = rig.fixture().handle();
    handle.insert_log(
        10,
        record("I", "dropbear[12]: <script>x</script>\u{1b}[0m\u{7}"),
    );
    handle.insert_log(11, record("I", "nginx[7]: worker started"));
    let (_, log) = rig.post("services/log", &[("name", DROPBEAR)]).await?;
    assert!(
        log.contains("&#60;script&#62;x&#60;/script&#62;[0m"),
        "{log}"
    );
    assert!(!log.contains("<script>"), "{log}");
    assert!(!log.contains('\u{1b}'), "{log}");
    assert!(!log.contains('\u{7}'), "{log}");
    assert!(!log.contains("worker started"), "{log}");
    assert!(
        !log.contains(&en(keys::WEB_SYSTEM_ENTWARE_SSH_LOG_EMPTY)),
        "{log}"
    );
    Ok(())
}

/// Todo 15: a host key that changed after the enrolment is refused before any sign-in,
/// and the answer shows the pinned and the presented fingerprint.
#[tokio::test]
async fn a_changed_host_key_shows_both_fingerprints() -> TestResult {
    let rig = enrolled().await?;
    let pinned = rig.fingerprint()?;
    let _new = rig.ssh().replace_host_key();
    let presented = rig.fingerprint()?;
    let offers = rig.counters().key_offers;
    let (_, body) = rig.post("services/list", &[]).await?;
    assert!(body.contains("id=\"entware-ssh-mismatch\""), "{body}");
    assert!(
        body.contains(&en(keys::WEB_SYSTEM_ENTWARE_SSH_MISMATCH)),
        "{body}"
    );
    assert!(body.contains(&format!("<code>{pinned}</code>")), "{body}");
    assert!(
        body.contains(&format!("<code>{presented}</code>")),
        "{body}"
    );
    assert_eq!(rig.counters().key_offers, offers, "no sign-in");
    assert!(
        rig.fixture()
            .audited("entware.ssh.hostkey_mismatch", "refused")?
    );
    Ok(())
}
