//! Network dialogs and changes whose router read fails: the failure is shown, and no
//! value read as missing preselects a choice or lets a change through.

use axum::http::StatusCode;
use kcc_i18n::keys;
use kcc_testkit::FaultInjection;

use crate::support::{
    outcome::TestResult,
    page::{en_with, form, text},
    web::Fixture,
};

/// `faults` with `show interface` answered only by `POST`.
///
/// Router detection reads it by `GET` and goes on without the interface inventory, so a
/// read failure injected on the `POST` reaches the page's own reads only.
fn without_listing(faults: FaultInjection) -> FaultInjection {
    faults.show_requires_post("show/interface")
}

/// W3-05: a network dialog whose router read fails shows the failure instead of a form
/// preselected from nothing (empty description, security level Private, DHCP addressing,
/// empty values).
#[tokio::test]
async fn a_dialog_whose_read_fails_shows_the_failure() -> TestResult {
    for (path, read) in [
        (
            "/ui/r/home/network/description?name=Bridge0",
            "\"interface\":{\"name\"",
        ),
        (
            "/ui/r/home/network/security-level?name=Bridge0",
            "\"interface\":{\"name\"",
        ),
        ("/ui/r/home/internet/address?name=ISP", "show/interface"),
        ("/ui/r/home/internet/create", "show/interface"),
        ("/ui/r/home/internet/edit/mtu?name=ISP", "show/interface"),
        (
            "/ui/r/home/wifi/edit/ssid?name=WifiMaster0/AccessPoint0",
            "show/interface",
        ),
        (
            "/ui/r/home/wifi/edit/schedule?name=WifiMaster0/AccessPoint0",
            "show/schedule",
        ),
    ] {
        let faults = without_listing(FaultInjection::default()).fail_read_matching(read, 100);
        let fixture = Fixture::with_faults(faults).await?;
        let admin = fixture.login("admin").await?;
        let answer = text(fixture.get(path, &admin).await?).await?;
        assert!(
            answer.contains(&en_with(keys::WEB_KIT_HTTP_ERROR, &[("status", "500")])),
            "{path}: {answer}"
        );
        assert!(!answer.contains("<form"), "{path} offers no form: {answer}");
    }
    Ok(())
}

/// W3-05: Add connection whose interface read fails is not planned with an empty list of
/// taken names, so an existing interface is never created over.
#[tokio::test]
async fn a_connection_is_not_created_when_the_names_cannot_be_read() -> TestResult {
    let faults =
        without_listing(FaultInjection::default()).fail_read_matching("show/interface", 100);
    let fixture = Fixture::with_faults(faults).await?;
    let operator = fixture.login("operator").await?;
    let answer = fixture
        .post(
            "/ui/r/home/internet/create",
            &operator,
            &form(&[("kind", "ipoe"), ("name", "Bridge0"), ("via", "")]),
        )
        .await?;
    assert_ne!(answer.status(), StatusCode::NOT_FOUND, "answered");
    assert_eq!(fixture.outcomes("web.wan_create")?, ["unreachable"]);
    assert!(
        fixture
            .handle()
            .request_log()
            .iter()
            .all(|record| record.command().is_none()),
        "nothing was sent"
    );
    Ok(())
}
