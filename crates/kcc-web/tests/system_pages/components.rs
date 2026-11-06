//! Components.
//!
//! Per-role controls, a component queued and read back, a refusal that sends nothing, the
//! update check the fake refuses, and the commit behind the typed router name that runs
//! as a job reporting its phases.

use core::{str, time::Duration};

use axum::http::StatusCode;
use futures_util::StreamExt as _;
use kcc_i18n::keys;
use kcc_rci::{RciBody, RciPath};
use serde_json::Value;
use tokio::time::{Instant, timeout_at};

use crate::{
    audited, en,
    support::{Fixture, ROUTER, TestResult, text},
};

/// The page under test.
const PAGE: &str = "/ui/r/home/system/components";

/// The components the fake router has queued for removal.
async fn removing(fixture: &Fixture) -> TestResult<Vec<String>> {
    let client = fixture.registry().client(ROUTER).await?;
    let path = RciPath::from_segments(["show", "components", "pending"])?;
    let RciBody::Json(reply) = client.show(&path, &()).await? else {
        return Err("show components pending is not JSON".into());
    };
    Ok(reply
        .value
        .get("remove")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect())
}

#[tokio::test]
async fn each_role_sees_the_components_and_only_its_controls() -> TestResult {
    let fixture = Fixture::new().await?;
    let remove = "hx-post=\"/ui/r/home/system/components/queue?name=wireguard&#38;action=remove\"";
    let check = "hx-post=\"/ui/r/home/system/components/check\"";
    let commit = "hx-post=\"/ui/r/home/system/components/commit\"";
    for (account, changes, commits) in [
        ("viewer", false, false),
        ("operator", true, false),
        ("admin", true, true),
    ] {
        let browser = fixture.login(account).await?;
        let response = fixture.get(PAGE, &browser).await?;
        assert_eq!(response.status(), StatusCode::OK, "{account}");
        let page = text(response).await?;
        for shown in [
            "5.1.3".to_owned(),
            ">wireguard<".to_owned(),
            en(keys::WEB_SYSTEM_COMPONENTS_INSTALLED),
            en(keys::WEB_SYSTEM_COMPONENTS_QUEUE_EMPTY),
        ] {
            assert!(page.contains(&shown), "{account} misses {shown}");
        }
        assert_eq!(page.contains(remove), changes, "{account} queue");
        assert_eq!(page.contains(check), changes, "{account} check");
        assert_eq!(page.contains(commit), commits, "{account} commit");
    }
    Ok(())
}

#[tokio::test]
async fn a_component_is_queued_and_read_back() -> TestResult {
    let fixture = Fixture::new().await?;
    let operator = fixture.login("operator").await?;
    for bad in [
        "name=teleport&action=remove",
        "name=wireguard&action=install",
        "name=wireguard&action=reinstall",
    ] {
        let response = fixture
            .post(&format!("{PAGE}/queue?{bad}"), &operator, "")
            .await?;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{bad}");
    }
    assert!(removing(&fixture).await?.is_empty(), "nothing queued");
    let body = text(
        fixture
            .post(
                &format!("{PAGE}/queue?name=wireguard&action=remove"),
                &operator,
                "",
            )
            .await?,
    )
    .await?;
    for expected in [
        "data-tone=\"success\"".to_owned(),
        "id=\"components-region\" hx-swap-oob=\"true\"".to_owned(),
        en(keys::WEB_SYSTEM_COMPONENTS_REMOVING),
    ] {
        assert!(body.contains(&expected), "missing {expected} in {body}");
    }
    assert_eq!(removing(&fixture).await?, ["wireguard"], "queued");
    assert!(
        audited(&fixture, "web.components_remove", "success")?,
        "audited"
    );
    Ok(())
}

#[tokio::test]
async fn the_update_check_shows_what_the_router_said() -> TestResult {
    let fixture = Fixture::new().await?;
    let operator = fixture.login("operator").await?;
    let body = text(
        fixture
            .post(&format!("{PAGE}/check"), &operator, "")
            .await?,
    )
    .await?;
    assert!(body.contains(&en(keys::WEB_KIT_REJECTED)), "{body}");
    assert!(
        body.contains(&en(keys::WEB_EXPLORER_ROUTER_SAID)),
        "router said"
    );
    assert!(
        audited(&fixture, "web.components_check", "rci_error")?,
        "audited"
    );
    Ok(())
}

#[tokio::test]
async fn the_commit_needs_the_router_name_and_runs_as_a_job() -> TestResult {
    let fixture = Fixture::new().await?;
    let commit = format!("{PAGE}/commit");
    let operator = fixture.login("operator").await?;
    let denied = fixture.post(&commit, &operator, "").await?;
    assert_eq!(denied.status(), StatusCode::FORBIDDEN, "operator");
    let admin = fixture.login("admin").await?;
    let asked = text(fixture.post(&commit, &admin, "").await?).await?;
    assert!(
        asked.contains(&en(keys::WEB_KIT_CONFIRM_DESTRUCTIVE_TITLE)),
        "asks: {asked}"
    );
    let panel = text(
        fixture
            .post(&commit, &admin, "confirm=yes&confirm_name=home")
            .await?,
    )
    .await?;
    let stream = panel
        .split_once("sse-connect=\"")
        .and_then(|(_, tail)| tail.split_once('"'))
        .map(|(url, _)| url.to_owned())
        .ok_or("no job stream")?;
    assert!(
        stream.starts_with("/ui/sse/r/home/system/jobs/job-"),
        "{stream}"
    );
    assert!(!panel.contains("/cancel\""), "a commit cannot stop halfway");
    let mut body = fixture
        .get(&stream, &admin)
        .await?
        .into_body()
        .into_data_stream();
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(60))
        .ok_or("deadline")?;
    let rebooting = en(keys::WEB_SYSTEM_COMPONENTS_REBOOTING);
    let mut received = String::new();
    while !received.contains(&rebooting) {
        let chunk = timeout_at(deadline, body.next())
            .await?
            .ok_or("stream ended")??;
        received.push_str(str::from_utf8(&chunk)?);
    }
    let committing = received
        .find(&en(keys::WEB_SYSTEM_COMPONENTS_COMMITTING))
        .ok_or("no committing line")?;
    assert!(
        committing < received.find(&rebooting).ok_or("no rebooting line")?,
        "in order: {received}"
    );
    assert!(
        fixture
            .audit()?
            .iter()
            .any(|entry| entry.action == "router.change_cli_terminal"
                && entry.target.as_deref() == Some("components commit")),
        "the commit went through the change workflow"
    );
    assert!(
        audited(&fixture, "web.components_commit", "started")?,
        "audited"
    );
    Ok(())
}
