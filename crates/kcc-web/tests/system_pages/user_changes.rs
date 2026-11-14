//! Router user changes.
//!
//! The tags of an account changed through the tag dialog, the typed-name delete that
//! spares the account kcc signs in with, and a router refusal in the router's own words.

use axum::http::StatusCode;
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_testkit::FaultInjection;

use crate::{
    audited, en, form, html,
    support::{Fixture, TestResult, header_text, text},
    users::{PAGE, add_lab, configured},
};

#[tokio::test]
async fn tags_change_and_a_delete_needs_the_typed_name() -> TestResult {
    let fixture = Fixture::new().await?;
    drop(add_lab(&fixture).await?);
    let admin = fixture.login("admin").await?;
    let tags = format!("{PAGE}/tags");
    let dialog = text(fixture.get(&format!("{tags}?name=lab"), &admin).await?).await?;
    assert!(
        dialog.contains("name=\"tag\" value=\"readonly\" checked"),
        "current tags checked: {dialog}"
    );
    let changed = text(
        fixture
            .post(
                &tags,
                &admin,
                &form(&[("name", "lab"), ("tag", "http"), ("confirm", "yes")]),
            )
            .await?,
    )
    .await?;
    assert!(
        changed.contains(&en(keys::WEB_KIT_DONE_UNSAVED)),
        "{changed}"
    );
    assert_eq!(
        configured(&fixture).await?,
        [("lab".to_owned(), vec!["http".to_owned()])],
        "cli and readonly removed, http added"
    );
    let delete = format!("{PAGE}/delete");
    let asked = text(fixture.get(&format!("{delete}?name=lab"), &admin).await?).await?;
    assert!(
        asked.contains("name=\"confirm_name\""),
        "typed name: {asked}"
    );
    let before = fixture.handle().request_count();
    let mistyped = fixture
        .post(
            &delete,
            &admin,
            &form(&[
                ("object", "lab"),
                ("confirm", "yes"),
                ("confirm_name", "Lab"),
            ]),
        )
        .await?;
    assert_eq!(mistyped.status(), StatusCode::UNPROCESSABLE_ENTITY, "422");
    assert!(
        text(mistyped)
            .await?
            .contains(&en(keys::WEB_ADMIN_ERROR_CONFIRM)),
        "mismatch"
    );
    let protected = fixture
        .post(
            &delete,
            &admin,
            &form(&[
                ("object", "admin"),
                ("confirm", "yes"),
                ("confirm_name", "admin"),
            ]),
        )
        .await?;
    assert!(
        text(protected)
            .await?
            .contains(&en(keys::WEB_SYSTEM_USERS_PROTECTED)),
        "kcc's own login"
    );
    assert_eq!(fixture.handle().request_count(), before, "nothing sent");
    let deleted = fixture
        .post(
            &delete,
            &admin,
            &form(&[
                ("object", "lab"),
                ("confirm", "yes"),
                ("confirm_name", "lab"),
            ]),
        )
        .await?;
    assert_eq!(
        header_text(&deleted, "hx-retarget").as_deref(),
        Some("#page-outcome"),
        "the outcome leaves the dialog"
    );
    assert!(configured(&fixture).await?.is_empty(), "gone");
    Ok(())
}

#[tokio::test]
async fn a_router_refusal_shows_only_what_the_router_said() -> TestResult {
    let fixture =
        Fixture::with_faults(FaultInjection::default().fail_parse_matching("user lab", 1)).await?;
    let body = add_lab(&fixture).await?;
    assert!(body.contains(&en(keys::WEB_KIT_REJECTED)), "{body}");
    assert!(
        body.contains(&en(keys::WEB_EXPLORER_ROUTER_SAID)),
        "router said"
    );
    assert!(!body.contains("unsaved-badge"), "no badge for a failure");
    assert!(
        audited(&fixture, "web.router_user_create", "rci_error")?,
        "audited"
    );
    assert!(
        !body.contains(&html(&tr(
            Locale::En,
            keys::MANAGEMENT_OUTCOME_UNKNOWN_ARMED,
            None
        ))),
        "the timer was disarmed"
    );
    Ok(())
}

#[tokio::test]
async fn a_tag_change_the_domain_refuses_is_audited_with_its_reason() -> TestResult {
    let fixture = Fixture::new().await?;
    let admin = fixture.login("admin").await?;
    let added = form(&[("name", "admin"), ("tag", "cli"), ("confirm", "yes")]);
    drop(fixture.post(PAGE, &admin, &added).await?);
    let refused = fixture
        .post(
            &format!("{PAGE}/tags"),
            &admin,
            &form(&[("name", "admin"), ("tag", "readonly"), ("confirm", "yes")]),
        )
        .await?;
    assert_eq!(refused.status(), StatusCode::UNPROCESSABLE_ENTITY, "422");
    assert!(
        text(refused)
            .await?
            .contains(&en(keys::WEB_SYSTEM_USERS_PROTECTED)),
        "the refusal in the dialog"
    );
    assert!(
        audited(&fixture, "web.router_user_tags", "failed")?,
        "audited with the domain's reason"
    );
    assert!(
        !audited(&fixture, "web.router_user_tags", "validation_failed")?,
        "not as a value that failed its check"
    );
    Ok(())
}

#[tokio::test]
async fn a_delete_the_domain_refuses_is_audited_with_its_reason() -> TestResult {
    let fixture = Fixture::new().await?;
    let admin = fixture.login("admin").await?;
    let refused = fixture
        .post(
            &format!("{PAGE}/delete"),
            &admin,
            &form(&[
                ("object", "admin"),
                ("confirm", "yes"),
                ("confirm_name", "admin"),
            ]),
        )
        .await?;
    assert_eq!(refused.status(), StatusCode::UNPROCESSABLE_ENTITY, "422");
    assert_eq!(
        header_text(&refused, "hx-retarget"),
        None,
        "the refusal stays in the dialog"
    );
    assert!(
        text(refused)
            .await?
            .contains(&en(keys::WEB_SYSTEM_USERS_PROTECTED)),
        "the refusal in the dialog"
    );
    assert!(
        audited(&fixture, "web.router_user_delete", "failed")?,
        "audited with the domain's reason"
    );
    assert!(
        !audited(&fixture, "web.router_user_delete", "validation_failed")?,
        "not as a value that failed its check"
    );
    Ok(())
}
