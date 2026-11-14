//! Router users.
//!
//! Per-role controls, an account added with its tags inside the fail-safe timer, and a
//! name refused before anything is sent.

use axum::http::StatusCode;
use kcc_i18n::keys;
use serde_json::{Value, json};

use crate::{
    cli_targets,
    support::{
        outcome::TestResult,
        page::{en, form, header_text, text},
        web::{Fixture, ROUTER},
    },
};

/// The page under test.
pub(crate) const PAGE: &str = "/ui/r/home/system/users";

/// The accounts the fake router's running configuration has: name and tags.
pub(crate) async fn configured(fixture: &Fixture) -> TestResult<Vec<(String, Vec<String>)>> {
    let client = fixture.registry().client(ROUTER).await?;
    let reply = client.show_rc(json!({"user": {}})).await?;
    Ok(reply
        .configuration_tree()
        .get("user")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|user| {
            let name = user.get("name")?.as_str()?.to_owned();
            let tags = user
                .get("tag")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect();
            Some((name, tags))
        })
        .collect())
}

/// Adds the account `lab` with the `cli` and `readonly` tags as `admin`, confirmed.
pub(crate) async fn add_lab(fixture: &Fixture) -> TestResult<String> {
    let admin = fixture.login("admin").await?;
    let fields = [
        ("name", "lab"),
        ("tag", "cli"),
        ("tag", "readonly"),
        ("confirm", "yes"),
    ];
    text(fixture.post(PAGE, &admin, &form(&fields)).await?).await
}

#[tokio::test]
async fn each_role_sees_the_accounts_and_only_its_controls() -> TestResult {
    let fixture = Fixture::new().await?;
    let add = "hx-get=\"/ui/r/home/system/users/new\"";
    for (account, adds) in [("viewer", false), ("operator", false), ("admin", true)] {
        let browser = fixture.login(account).await?;
        let response = fixture.get(PAGE, &browser).await?;
        assert_eq!(response.status(), StatusCode::OK, "{account}");
        let page = text(response).await?;
        for shown in [
            en(keys::WEB_SYSTEM_USERS_TITLE),
            en(keys::WEB_SYSTEM_USERS_EMPTY),
            "href=\"/ui/r/home/system/services\"".to_owned(),
            "<a class=\"tabs__link\" href=\"/ui/r/home/system/users\" aria-current=\"page\">"
                .to_owned(),
            "id=\"page-outcome\"".to_owned(),
        ] {
            assert!(page.contains(&shown), "{account} misses {shown}");
        }
        assert_eq!(page.contains(add), adds, "{account} add");
    }
    let operator = fixture.login("operator").await?;
    let refused = fixture
        .post(
            PAGE,
            &operator,
            &form(&[("name", "lab"), ("confirm", "yes")]),
        )
        .await?;
    assert_eq!(refused.status(), StatusCode::FORBIDDEN, "the route checks");
    let dialog = fixture.get(&format!("{PAGE}/new"), &operator).await?;
    assert_eq!(dialog.status(), StatusCode::FORBIDDEN, "no dialog either");
    assert!(
        fixture.audited("web.router_user_create", "forbidden")?,
        "audited"
    );
    let missing = fixture.get("/ui/r/cottage/system/users", &operator).await?;
    assert_eq!(missing.status(), StatusCode::NOT_FOUND, "unknown router");
    Ok(())
}

#[tokio::test]
async fn an_account_is_added_with_its_tags_inside_the_fail_safe_timer() -> TestResult {
    let fixture = Fixture::new().await?;
    let admin = fixture.login("admin").await?;
    let dialog = text(fixture.get(&format!("{PAGE}/new"), &admin).await?).await?;
    assert!(
        dialog.contains("name=\"tag\" value=\"cli\""),
        "tags from the catalog: {dialog}"
    );
    assert!(!dialog.contains("value=\"rights.\""), "no prefix families");
    let unconfirmed = fixture
        .post(PAGE, &admin, &form(&[("name", "lab"), ("tag", "cli")]))
        .await?;
    assert_eq!(
        header_text(&unconfirmed, "hx-retarget").as_deref(),
        Some("#dialog-content"),
        "asks first"
    );
    let prompt = text(unconfirmed).await?;
    assert!(
        prompt.contains(&en(keys::WEB_KIT_CONFIRM_MANAGEMENT_TITLE)),
        "the fail-safe dialog: {prompt}"
    );
    assert!(
        prompt.contains("hx-post=\"/ui/r/home/system/users?name=lab&#38;tag=cli\""),
        "sends the names again: {prompt}"
    );
    assert!(configured(&fixture).await?.is_empty(), "nothing yet");
    let body = add_lab(&fixture).await?;
    for expected in [
        en(keys::WEB_KIT_DONE_UNSAVED),
        "id=\"users-region\" aria-labelledby=\"users-title\" hx-swap-oob=\"true\"".to_owned(),
        "cli, readonly".to_owned(),
    ] {
        assert!(body.contains(&expected), "missing {expected} in {body}");
    }
    assert_eq!(
        configured(&fixture).await?,
        [(
            "lab".to_owned(),
            vec!["cli".to_owned(), "readonly".to_owned()]
        )],
        "read back"
    );
    let fail_safe = cli_targets(&fixture)?
        .into_iter()
        .filter(|target| target == "system configuration fail-safe timer")
        .count();
    assert_eq!(fail_safe, 2, "armed, then disarmed");
    assert!(
        fixture.audited("web.router_user_create", "success")?,
        "audited"
    );
    Ok(())
}

#[tokio::test]
async fn an_invalid_name_is_refused_before_anything_is_sent() -> TestResult {
    let fixture = Fixture::new().await?;
    let admin = fixture.login("admin").await?;
    drop(fixture.get(PAGE, &admin).await?);
    let before = fixture.handle().request_count();
    let response = fixture
        .post(
            PAGE,
            &admin,
            &form(&[("name", "lab user"), ("tag", "cli"), ("confirm", "yes")]),
        )
        .await?;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY, "422");
    assert_eq!(
        header_text(&response, "hx-retarget").as_deref(),
        Some("#dialog-content"),
        "back into the dialog"
    );
    let body = text(response).await?;
    assert!(
        body.contains(&en(keys::WEB_SYSTEM_USERS_NAME_ERROR)),
        "the rule: {body}"
    );
    assert!(body.contains("value=\"lab user\""), "as typed");
    assert!(
        body.contains("name=\"tag\" value=\"cli\" checked"),
        "tags kept"
    );
    assert_eq!(fixture.handle().request_count(), before, "nothing sent");
    assert!(
        fixture.audited("web.router_user_create", "validation_failed")?,
        "audited"
    );
    Ok(())
}
