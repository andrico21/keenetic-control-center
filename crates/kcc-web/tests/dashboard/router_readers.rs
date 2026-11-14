//! The router form's read-only polling login: sealed, used by the poller, never rendered
//! or audited, and removable.

use axum::http::StatusCode;
use kcc_testkit::{DEFAULT_LOGIN, model::Profile};
use serde_json::json;

use crate::{
    router_credentials::{audit_holds, audited, dummy, origin, sealed},
    support::{
        outcome::TestResult,
        page::{form, text},
    },
    tests::{ROUTER_LOGIN, ROUTER_SECRET, fleet},
};

/// A read-only pair saved on the edit form is sealed and is what the poller signs in
/// with: a wrong reader password fails the poll while the management login still works.
#[tokio::test]
async fn a_read_only_pair_saved_on_the_form_is_what_the_poller_signs_in_with() -> TestResult {
    let fixture = fleet(&[("home", Profile::default())]).await?;
    let browser = fixture.login("router-manager").await?;
    let url = origin(&fixture, "home")?;
    let wrong = dummy("reader")?;
    for (secret, polls) in [(wrong.as_str(), false), (ROUTER_SECRET, true)] {
        let body = form(&[
            ("router", "home"),
            ("url", &url),
            ("login", DEFAULT_LOGIN),
            ("auth", "auto"),
            ("password", ""),
            ("tls", "verify"),
            ("read_login", ROUTER_LOGIN),
            ("read_password", secret),
            ("tags", ""),
        ]);

        let response = fixture
            .post("/ui/routers/home/edit", &browser, &body)
            .await?;

        assert_eq!(response.status(), StatusCode::OK, "saved");
        let stored = fixture.registry().get("home")?.profile;
        assert_eq!(
            stored.read_login.as_deref(),
            Some(ROUTER_LOGIN),
            "reader login"
        );
        assert_eq!(
            stored.read_password_file,
            Some(sealed(&fixture, "home.read.sealed")),
            "the profile points at the sealed reader password"
        );
        assert_eq!(
            fixture.registry().poll_info("home").await.is_ok(),
            polls,
            "poll"
        );
        assert!(
            fixture.registry().client("home").await.is_ok(),
            "management login"
        );
    }
    assert_eq!(audited(&fixture, "router.profile_update")?, json!(["read"]),);
    assert!(
        !audit_holds(&fixture, &wrong)?,
        "no reader password in the audit log"
    );
    Ok(())
}

/// "Remove read-only login" clears both fields and deletes the sealed record.
#[tokio::test]
async fn removing_the_read_only_login_clears_it_and_its_sealed_record() -> TestResult {
    let fixture = fleet(&[("home", Profile::default())]).await?;
    let browser = fixture.login("router-manager").await?;
    let url = origin(&fixture, "home")?;
    let reader = dummy("reader")?;
    let save = form(&[
        ("router", "home"),
        ("url", &url),
        ("login", DEFAULT_LOGIN),
        ("tls", "verify"),
        ("read_login", ROUTER_LOGIN),
        ("read_password", &reader),
    ]);
    assert_eq!(
        fixture
            .post("/ui/routers/home/edit", &browser, &save)
            .await?
            .status(),
        StatusCode::OK
    );
    assert!(
        sealed(&fixture, "home.read.sealed").is_file(),
        "precondition"
    );
    let edit = text(fixture.get("/ui/routers/home/edit", &browser).await?).await?;
    assert!(
        edit.contains("name=\"clear_read\""),
        "the remove box is offered"
    );
    assert!(
        !edit.contains(&reader),
        "the reader password is never rendered"
    );
    let body = form(&[
        ("router", "home"),
        ("url", &url),
        ("login", DEFAULT_LOGIN),
        ("tls", "verify"),
        ("read_login", ROUTER_LOGIN),
        ("read_password", ""),
        ("clear_read", "on"),
    ]);

    let response = fixture
        .post("/ui/routers/home/edit", &browser, &body)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let stored = fixture.registry().get("home")?.profile;
    assert_eq!(stored.read_login, None, "reader login cleared");
    assert_eq!(stored.read_password_file, None, "reader password cleared");
    assert!(
        !sealed(&fixture, "home.read.sealed").exists(),
        "sealed record removed"
    );
    assert_eq!(audited(&fixture, "router.profile_update")?, json!(["read"]),);
    assert!(
        !audit_holds(&fixture, &reader)?,
        "no reader password in the audit log"
    );
    Ok(())
}
