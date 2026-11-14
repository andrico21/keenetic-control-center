//! What a delete refuses: a viewer, a name that is not the router's, and a segment that
//! changed after its dialog opened; none of them sends anything to the router.

use axum::http::StatusCode;
use kcc_i18n::keys;

use crate::{
    PAGE, SEGMENT, create, delete_dialog, said, segment, sent_lines,
    support::{Fixture, TestResult, text},
};

/// A mistyped name, and a name that is not the router's even if typed as sent, delete
/// nothing; the dialog comes back with the error and still shows what would go.
#[tokio::test]
async fn a_name_that_is_not_the_routers_deletes_nothing() -> TestResult {
    let fixture = Fixture::new().await?;
    let admin = fixture.login("admin").await?;
    drop(create(&fixture, &admin, &SEGMENT).await?);
    let (_dialog, action) = delete_dialog(&fixture, &admin, "23").await?;
    let running = fixture.handle().running_config_text();
    let lines = sent_lines(&fixture);
    let wrong = fixture
        .post(&action, &admin, "object=home&confirm=yes&confirm_name=Home")
        .await?;
    assert_eq!(
        wrong.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "wrong name"
    );
    let refused = text(wrong).await?;
    assert!(
        refused.contains(&said(keys::WEB_ADMIN_ERROR_CONFIRM)),
        "says so: {refused}"
    );
    assert!(
        refused.contains("interface Bridge23"),
        "still shows what goes"
    );
    let tampered = fixture
        .post(
            &action,
            &admin,
            "object=Bridge23&confirm=yes&confirm_name=Bridge23",
        )
        .await?;
    assert_eq!(
        tampered.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "only the router's name confirms"
    );
    assert_eq!(sent_lines(&fixture), lines, "nothing sent");
    assert_eq!(
        fixture.handle().running_config_text(),
        running,
        "the segment stays"
    );
    let mismatches = fixture
        .audit()?
        .iter()
        .filter(|entry| {
            entry.action == "web.segments_delete" && entry.outcome == "confirmation_mismatch"
        })
        .count();
    assert_eq!(mismatches, 2, "audited");
    Ok(())
}

/// A viewer reads the list but sees no delete; the dialog and the delete answer 403.
#[tokio::test]
async fn a_viewer_sees_no_delete_and_is_refused() -> TestResult {
    let fixture = Fixture::new().await?;
    let admin = fixture.login("admin").await?;
    drop(create(&fixture, &admin, &SEGMENT).await?);
    let (_dialog, action) = delete_dialog(&fixture, &admin, "23").await?;
    let running = fixture.handle().running_config_text();
    let viewer = fixture.login("viewer").await?;
    let page = text(fixture.get(PAGE, &viewer).await?).await?;
    let listed = segment(&page, "23").ok_or("the viewer sees the segment")?;
    assert!(listed.contains("Bridge23"), "listed: {listed}");
    assert!(
        !page.contains("segments/delete"),
        "no delete control: {page}"
    );
    let dialog = fixture
        .get(&format!("{PAGE}/delete?id=23"), &viewer)
        .await?;
    assert_eq!(dialog.status(), StatusCode::FORBIDDEN, "no dialog");
    let lines = sent_lines(&fixture);
    let refused = fixture
        .post(
            &action,
            &viewer,
            "object=home&confirm=yes&confirm_name=home",
        )
        .await?;
    assert_eq!(refused.status(), StatusCode::FORBIDDEN, "no delete");
    assert_eq!(sent_lines(&fixture), lines, "nothing sent");
    assert_eq!(
        fixture.handle().running_config_text(),
        running,
        "the segment stays"
    );
    assert!(
        fixture
            .audit()?
            .iter()
            .any(|entry| entry.action == "web.segments_delete" && entry.outcome == "forbidden"),
        "audited"
    );
    Ok(())
}

/// A dialog opened before the segment was deleted and made again on another port deletes
/// nothing: what it showed is no longer what would go.
#[tokio::test]
async fn a_segment_changed_after_its_dialog_opened_is_not_deleted() -> TestResult {
    let fixture = Fixture::new().await?;
    let admin = fixture.login("admin").await?;
    drop(create(&fixture, &admin, &SEGMENT).await?);
    let (_stale_dialog, stale) = delete_dialog(&fixture, &admin, "23").await?;
    let (_dialog, current) = delete_dialog(&fixture, &admin, "23").await?;
    assert_eq!(current, stale, "the same segment opens the same dialog");
    let deleted = fixture
        .post(
            &current,
            &admin,
            "object=home&confirm=yes&confirm_name=home",
        )
        .await?;
    assert_eq!(deleted.status(), StatusCode::OK, "deleted in between");
    let other_port: Vec<(&str, &str)> = SEGMENT
        .iter()
        .map(|&(field, value)| {
            (
                field,
                if field == "port" {
                    "GigabitEthernet0/4"
                } else {
                    value
                },
            )
        })
        .collect();
    drop(create(&fixture, &admin, &other_port).await?);
    let running = fixture.handle().running_config_text();
    let lines = sent_lines(&fixture);
    let refused = fixture
        .post(&stale, &admin, "object=home&confirm=yes&confirm_name=home")
        .await?;
    assert_eq!(
        refused.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "refused"
    );
    let body = text(refused).await?;
    assert!(
        body.contains(&said(keys::WEB_SEGMENTS_DELETE_CHANGED)),
        "says why: {body}"
    );
    assert!(
        body.contains("GigabitEthernet0/4"),
        "and shows what would go now: {body}"
    );
    assert_eq!(sent_lines(&fixture), lines, "nothing sent");
    assert_eq!(
        fixture.handle().running_config_text(),
        running,
        "the new segment stays"
    );
    Ok(())
}
