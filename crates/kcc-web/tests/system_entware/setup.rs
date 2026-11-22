//! The setup: the typed router name first, then a job followed to its end.
//!
//! The job stream ends by offering the save, which the job never makes; drives outside the
//! router's list and a missing installer choice are refused in the user's words, before
//! `opkg disk` is sent.

use core::{str, time::Duration};

use axum::http::StatusCode;
use futures_util::StreamExt as _;
use kcc_i18n::keys;
use kcc_testkit::model::Model;
use tokio::time::{Instant, timeout_at};

use super::{DRIVE, PAGE, heard, heard_since, mark, model, over, ready};
use crate::support::{
    outcome::TestResult,
    page::{en, en_with, form, text},
    web::{Browser, Fixture},
};

/// The aarch64 installer of the closed table, independent of the code under test.
const AARCH64_URL: &str =
    "https://bin.entware.net/aarch64-k3.10/installer/aarch64-installer.tar.gz";

/// Everything the job stream at `stream` sends until it is done.
async fn followed(fixture: &Fixture, browser: &Browser, stream: &str) -> TestResult<String> {
    let mut body = fixture
        .get(stream, browser)
        .await?
        .into_body()
        .into_data_stream();
    let deadline = Instant::now()
        .checked_add(Duration::from_hours(2))
        .ok_or("deadline")?;
    let mut received = String::new();
    while !received.contains("event: done") {
        let chunk = timeout_at(deadline, body.next())
            .await?
            .ok_or("stream ended")??;
        received.push_str(str::from_utf8(&chunk)?);
    }
    Ok(received)
}

/// Todo 12: the setup asks for the router name, then runs as a job that offers the save.
///
/// Nothing is sent before the name; confirmed, the job's stream reports the installer's
/// steps and ends with the save offered; the router has `opkg disk` with the aarch64
/// installer and was never asked to save.
#[tokio::test(start_paused = true)]
async fn the_setup_runs_as_a_job_and_offers_the_save() -> TestResult {
    let fixture = over(ready()).await?;
    let admin = fixture.login("admin").await?;
    let path = format!("{PAGE}/setup");
    let before = mark(&fixture);
    let asked = text(
        fixture
            .post(&path, &admin, &form(&[("drive", DRIVE)]))
            .await?,
    )
    .await?;
    assert!(
        asked.contains(&en(keys::WEB_KIT_CONFIRM_DESTRUCTIVE_TITLE)),
        "{asked}"
    );
    assert!(asked.contains("setup?drive=fixture-media%3A%2F"), "{asked}");
    assert_eq!(
        heard_since(&fixture, before),
        Vec::<String>::new(),
        "nothing sent before the router name"
    );
    let confirmed = [
        ("drive", DRIVE),
        ("confirm", "yes"),
        ("confirm_name", "home"),
    ];
    let panel = text(fixture.post(&path, &admin, &form(&confirmed)).await?).await?;
    assert!(
        panel.contains(&en(keys::WEB_SYSTEM_ENTWARE_SETUP_JOB)),
        "{panel}"
    );
    assert!(
        !panel.contains("/cancel\""),
        "the setup cannot stop halfway"
    );
    let stream = panel
        .split_once("sse-connect=\"")
        .and_then(|(_, tail)| tail.split_once('"'))
        .map(|(url, _)| url.to_owned())
        .ok_or("no job stream")?;
    let received = followed(&fixture, &admin, &stream).await?;
    for line in [
        en(keys::WEB_SYSTEM_ENTWARE_STEP_INSTALL),
        en_with(keys::WEB_SYSTEM_ENTWARE_STEP_VERIFY, &[("value", "1")]),
        en(keys::WEB_SYSTEM_ENTWARE_STEP_READ_BACK),
        en(keys::WEB_SYSTEM_ENTWARE_STEP_DONE),
        en(keys::WEB_EXPLORER_JOB_COMPLETED),
        "hx-post=\"/ui/r/home/save\"".to_owned(),
    ] {
        assert!(received.contains(&line), "missing {line} in {received}");
    }
    assert_eq!(
        received.matches("/ui/r/home/save").count(),
        1,
        "the save follows the last line only: {received}"
    );
    assert!(
        !received.contains("hx-trigger"),
        "the save waits for a click: {received}"
    );
    assert!(heard(&fixture, &format!("opkg disk {DRIVE} {AARCH64_URL}")));
    assert!(
        heard_since(&fixture, before)
            .iter()
            .all(|line| !line.contains("configuration save")),
        "the job never saves"
    );
    assert!(fixture.audited("web.entware_setup", "started")?);
    Ok(())
}

/// Todo 12: a drive the router does not list is refused in the user's words and never
/// reaches a command; so is a setup without a drive, which does not even ask first.
#[tokio::test]
async fn a_drive_outside_the_list_is_refused() -> TestResult {
    let fixture = over(ready()).await?;
    let admin = fixture.login("admin").await?;
    let path = format!("{PAGE}/setup");
    let hostile = "evil:/;reboot";
    let confirmed = [
        ("drive", hostile),
        ("confirm", "yes"),
        ("confirm_name", "home"),
    ];
    let body = text(fixture.post(&path, &admin, &form(&confirmed)).await?).await?;
    assert!(
        body.contains(&en(keys::WEB_SYSTEM_ENTWARE_DRIVE_NOT_ELIGIBLE)),
        "{body}"
    );
    assert!(
        !heard(&fixture, "opkg disk"),
        "never spliced into a command"
    );
    assert!(!heard(&fixture, "reboot"), "never spliced into a command");
    let before = mark(&fixture);
    let empty = text(fixture.post(&path, &admin, "").await?).await?;
    assert!(
        empty.contains(&en(keys::WEB_SYSTEM_ENTWARE_DRIVE_NOT_ELIGIBLE)),
        "{empty}"
    );
    assert_eq!(mark(&fixture), before, "nothing read or sent");
    assert!(fixture.audited("web.entware_setup", "validation_failed")?);
    Ok(())
}

/// Todo 12: on a MIPS router the setup without an installer choice is refused in the
/// user's words; an installer outside the table is not one of the page's values.
#[tokio::test]
async fn a_mips_router_needs_the_installer_choice() -> TestResult {
    let fixture = over(model(Model::Kn1010)).await?;
    let admin = fixture.login("admin").await?;
    let path = format!("{PAGE}/setup");
    let confirmed = [
        ("drive", DRIVE),
        ("confirm", "yes"),
        ("confirm_name", "home"),
    ];
    let body = text(fixture.post(&path, &admin, &form(&confirmed)).await?).await?;
    assert!(
        body.contains(&en(keys::WEB_SYSTEM_ENTWARE_INSTALLER_REQUIRED)),
        "{body}"
    );
    let bogus = [
        ("drive", DRIVE),
        ("installer", "https://example.com/x.tar.gz"),
        ("confirm", "yes"),
        ("confirm_name", "home"),
    ];
    let response = fixture.post(&path, &admin, &form(&bogus)).await?;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(!heard(&fixture, "opkg disk"), "nothing installed");
    Ok(())
}
