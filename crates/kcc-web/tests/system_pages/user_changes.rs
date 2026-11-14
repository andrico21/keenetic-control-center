//! Router user changes.
//!
//! The tags of an account changed through the tag dialog, the delete that spares the
//! account kcc signs in with, and a router refusal in the router's own words.

use axum::http::StatusCode;
use kcc_i18n::keys;

use crate::{
    support::{
        outcome::TestResult,
        page::{en, form, header_text, text},
        refusal::{Refusal, router_refusals},
        web::Fixture,
    },
    users::{PAGE, add_lab, configured},
};

#[tokio::test]
async fn tags_change_and_kccs_own_login_is_never_deleted() -> TestResult {
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
    let before = fixture.handle().request_count();
    let protected = fixture
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
    assert!(
        text(protected)
            .await?
            .contains(&en(keys::WEB_SYSTEM_USERS_PROTECTED)),
        "kcc's own login"
    );
    assert_eq!(fixture.handle().request_count(), before, "nothing sent");
    Ok(())
}

#[tokio::test]
async fn a_router_refusal_shows_only_what_the_router_said() -> TestResult {
    let lab = form(&[
        ("name", "lab"),
        ("tag", "cli"),
        ("tag", "readonly"),
        ("confirm", "yes"),
    ]);
    router_refusals(&[Refusal {
        action: "web.router_user_create",
        refused: "user lab",
        account: "admin",
        post: (PAGE, &lab),
        unsaid: "user lab",
        absent: &["unsaved-badge"],
        unchanged: false,
    }])
    .await
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
        fixture.audited("web.router_user_tags", "failed")?,
        "audited with the domain's reason"
    );
    assert!(
        !fixture.audited("web.router_user_tags", "validation_failed")?,
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
        fixture.audited("web.router_user_delete", "failed")?,
        "audited with the domain's reason"
    );
    assert!(
        !fixture.audited("web.router_user_delete", "validation_failed")?,
        "not as a value that failed its check"
    );
    Ok(())
}
