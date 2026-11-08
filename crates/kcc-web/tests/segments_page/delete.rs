//! A created segment listed and deleted with its router's name, and a partial segment
//! listed and deleted; the router ends where it started.

use axum::http::StatusCode;
use kcc_i18n::keys;

use crate::{
    PAGE, SEGMENT, create, delete_dialog, said, segment,
    support::{Fixture, ROUTER, TestResult, header_text, text},
};

/// Create, list, delete: the router's settings and running configuration come back.
#[tokio::test]
async fn a_created_segment_is_listed_then_deleted_back_to_the_start() -> TestResult {
    let fixture = Fixture::new().await?;
    let settings = fixture.handle().settings_snapshot();
    let running = fixture.handle().running_config_text();
    let operator = fixture.login("operator").await?;
    let created = create(&fixture, &operator, &SEGMENT).await?;
    assert!(
        created.contains("id=\"segments-region\" hx-swap-oob=\"true\""),
        "the list is read back: {created}"
    );
    let page = text(fixture.get(PAGE, &operator).await?).await?;
    let listed = segment(&page, "23").ok_or("the segment's panel")?;
    for expected in [
        "Bridge23",
        "198.51.100.1/24",
        "198.51.100.10",
        "198.51.100.50",
        "GigabitEthernet0/1",
        "WifiMaster0/AccessPoint1",
        "hx-get=\"/ui/r/home/segments/delete?id=23\"",
    ] {
        assert!(listed.contains(expected), "{expected} in {listed}");
    }
    assert!(
        !listed.contains(&said(keys::WEB_SEGMENTS_INCOMPLETE)),
        "complete: {listed}"
    );
    let (dialog, action) = delete_dialog(&fixture, &operator, "23").await?;
    for expected in [
        "interface Vlan23",
        "interface Bridge23",
        "ip dhcp pool Pool23",
        "GigabitEthernet0/1",
        "name=\"name\" value=\"home\"",
    ] {
        assert!(dialog.contains(expected), "{expected} in {dialog}");
    }
    assert!(
        action.starts_with("/ui/r/home/segments/delete?id=23&seen="),
        "{action}"
    );
    let deleted = fixture
        .post(&action, &operator, "name=home&confirm=home")
        .await?;
    assert_eq!(deleted.status(), StatusCode::OK, "deleted");
    assert_eq!(
        header_text(&deleted, "hx-retarget").as_deref(),
        Some("#page-outcome"),
        "answered into the page"
    );
    assert_eq!(
        header_text(&deleted, "hx-trigger").as_deref(),
        Some("kcc:dialog-close"),
        "the dialog closes"
    );
    let answer = text(deleted).await?;
    assert!(
        answer.contains(&said(keys::WEB_KIT_DONE)),
        "applied, and nothing is left unsaved: {answer}"
    );
    assert!(
        answer.contains(&said(keys::WEB_SEGMENTS_EMPTY)),
        "the list read back is empty: {answer}"
    );
    assert_eq!(
        fixture.handle().settings_snapshot(),
        settings,
        "the settings tree is back"
    );
    assert_eq!(
        fixture.handle().running_config_text(),
        running,
        "the running configuration is back"
    );
    let audit = fixture.audit()?;
    let outcomes: Vec<&str> = audit
        .iter()
        .filter(|entry| entry.action == "web.segments_delete")
        .map(|entry| entry.outcome.as_str())
        .collect();
    assert_eq!(outcomes, ["success"], "audited");
    Ok(())
}

/// A segment missing a piece is listed as incomplete, and its delete removes what is left.
#[tokio::test]
async fn a_partial_segment_is_listed_and_deletable() -> TestResult {
    let fixture = Fixture::new().await?;
    let running = fixture.handle().running_config_text();
    let admin = fixture.login("admin").await?;
    drop(create(&fixture, &admin, &SEGMENT).await?);
    let client = fixture.registry().client(ROUTER).await?;
    drop(client.parse("no ip nat Bridge23").await?);
    let page = text(fixture.get(PAGE, &admin).await?).await?;
    let listed = segment(&page, "23").ok_or("the partial segment's panel")?;
    assert!(
        listed.contains(&said(keys::WEB_SEGMENTS_INCOMPLETE)),
        "flagged: {listed}"
    );
    assert!(listed.contains(&said(keys::COMMON_NO)), "no NAT: {listed}");
    let (_dialog, action) = delete_dialog(&fixture, &admin, "23").await?;
    let deleted = fixture
        .post(&action, &admin, "name=home&confirm=home")
        .await?;
    assert_eq!(deleted.status(), StatusCode::OK, "deleted");
    let answer = text(deleted).await?;
    assert!(
        answer.contains(&said(keys::WEB_KIT_DONE)),
        "applied: {answer}"
    );
    assert_eq!(
        fixture.handle().running_config_text(),
        running,
        "nothing of it is left"
    );
    Ok(())
}
