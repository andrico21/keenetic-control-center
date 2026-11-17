//! Router account passwords: set when an account is added and changed later, both as
//! management changes confirmed in their dialog; the account kcc signs in with is refused.

use axum::http::StatusCode;
use kcc_i18n::keys;

use crate::{
    ROUTER, TraceCapture, dummy, nowhere, setup, stored,
    support::{
        outcome::TestResult,
        page::{assert_native_post, en_with, text},
        web::{Browser, Fixture},
    },
};

/// The password dialog of `alice`.
const ALICE: &str = "/ui/r/prod-1/system/users/password?name=alice";

/// The stored password digest of `name`: `md5 <hex>`.
fn digest(fixture: &Fixture, name: &str) -> TestResult<Option<String>> {
    let config = fixture.router(ROUTER)?.running_config_text();
    Ok(stored(&config, &format!("user {name}"), "password "))
}

/// Posts `fields` to `path` as `browser`: the status and the body.
async fn post(
    fixture: &Fixture,
    browser: &Browser,
    (path, fields): (&str, &[(&str, &str)]),
) -> TestResult<(StatusCode, String)> {
    let response = fixture.post_form(path, browser, fields).await?;
    Ok((response.status(), text(response).await?))
}

#[tokio::test]
async fn account_passwords_reach_the_router_and_nothing_else() -> TestResult {
    let trace = TraceCapture::install();
    let fixture = setup::fixture().await?;
    let admin = fixture.login("admin").await?;
    let first = dummy("alice", 1);
    let add = text(fixture.get("/ui/r/prod-1/system/users/new", &admin).await?).await?;
    assert_native_post(&add)?;
    assert!(
        add.contains("name=\"secret\" type=\"password\" value=\"\" autocomplete=\"new-password\""),
        "the add dialog's write-only password: {add}"
    );
    let added = [
        ("name", "alice"),
        ("confirm", "yes"),
        ("secret", first.as_str()),
        ("secret_again", first.as_str()),
    ];
    let (add_status, created) =
        post(&fixture, &admin, ("/ui/r/prod-1/system/users", &added)).await?;
    assert_eq!(add_status, StatusCode::OK, "added: {created}");
    let set = digest(&fixture, "alice")?.ok_or("no password stored")?;
    let hex = set.strip_prefix("md5 ").ok_or("not a digest")?;
    assert_eq!(hex.len(), 32, "a digest of the expected length");
    let page = text(fixture.get("/ui/r/prod-1/system/users", &admin).await?).await?;
    assert!(
        page.contains(&format!("hx-get=\"{ALICE}\"")),
        "Set password: {page}"
    );
    let dialog = text(fixture.get(ALICE, &admin).await?).await?;
    assert_native_post(&dialog)?;
    assert!(
        dialog.contains("<input type=\"hidden\" name=\"confirm\" value=\"yes\">"),
        "Apply confirms in the dialog: {dialog}"
    );
    let second = dummy("alice", 2);
    let change = [
        ("confirm", "yes"),
        ("secret", second.as_str()),
        ("secret_again", second.as_str()),
    ];
    let (change_status, changed) = post(&fixture, &admin, (ALICE, &change)).await?;
    assert_eq!(change_status, StatusCode::OK, "changed: {changed}");
    let what = en_with(keys::WEB_INTERNET_PASSWORD, &[]);
    assert!(
        changed.contains(&en_with(keys::WEB_SECRET_CHANGED, &[("what", &what)])),
        "the read-back's verdict: {changed}"
    );
    assert_ne!(digest(&fixture, "alice")?, Some(set), "a new password");
    let served = [add, created, page, dialog, changed];
    for secret in [&first, &second] {
        nowhere(secret, &served, (&fixture, &trace))?;
    }
    assert_eq!(
        fixture.outcomes("web.router_user_password")?,
        ["success"],
        "audited"
    );
    Ok(())
}

#[tokio::test]
async fn native_get_ignores_secret_query_values_and_sends_nothing() -> TestResult {
    let fixture = setup::fixture().await?;
    let admin = fixture.login("admin").await?;
    let named = [("name", "alice"), ("confirm", "yes")];
    let (add_status, _) = post(&fixture, &admin, ("/ui/r/prod-1/system/users", &named)).await?;
    assert_eq!(add_status, StatusCode::OK, "alice added");
    let before = fixture.router(ROUTER)?.request_count();
    let secret = ["native", "query", "secret"].join("-");
    let again = ["native", "query", "repeat"].join("-");
    let path = format!("{ALICE}&secret={secret}&secret_again={again}");

    let response = fixture.get(&path, &admin).await?;
    let body = text(response).await?;

    assert!(
        !body.contains(&secret) && !body.contains(&again),
        "query secrets reflected"
    );
    assert_eq!(
        fixture.router(ROUTER)?.request_count(),
        before,
        "the router heard nothing"
    );
    Ok(())
}

#[tokio::test]
async fn refused_entries_and_the_login_kcc_uses_send_nothing() -> TestResult {
    let fixture = setup::fixture().await?;
    let admin = fixture.login("admin").await?;
    let named = [("name", "alice"), ("confirm", "yes")];
    let (add_status, _) = post(&fixture, &admin, ("/ui/r/prod-1/system/users", &named)).await?;
    assert_eq!(add_status, StatusCode::OK, "added without a password");
    drop(fixture.get(ALICE, &admin).await?);
    let before = fixture.router(ROUTER)?.request_count();
    let (typed, other) = (dummy("alice", 3), dummy("alice", 4));
    let mismatch = [
        ("confirm", "yes"),
        ("secret", typed.as_str()),
        ("secret_again", other.as_str()),
    ];
    let (differ_status, differ) = post(&fixture, &admin, (ALICE, &mismatch)).await?;
    assert_eq!(
        differ_status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "different entries"
    );
    assert!(
        differ.contains(&en_with(keys::WEB_SECRET_MISMATCH, &[])),
        "says so: {differ}"
    );
    let unconfirmed = [("secret", typed.as_str()), ("secret_again", typed.as_str())];
    let (asked_status, asked) = post(&fixture, &admin, (ALICE, &unconfirmed)).await?;
    assert_eq!(
        asked_status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "no confirmation"
    );
    assert!(
        asked.contains(&en_with(keys::WEB_SECRET_CONFIRM, &[])),
        "says so: {asked}"
    );
    let login = "/ui/r/prod-1/system/users/password?name=admin";
    let confirmed = [
        ("confirm", "yes"),
        ("secret", typed.as_str()),
        ("secret_again", typed.as_str()),
    ];
    let (protected_status, protected) = post(&fixture, &admin, (login, &confirmed)).await?;
    assert_eq!(
        protected_status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "kcc's own login"
    );
    assert!(
        protected.contains(&en_with(keys::WEB_SECRET_USER_PROTECTED, &[])),
        "the localized refusal: {protected}"
    );
    let shown = text(fixture.get(login, &admin).await?).await?;
    assert!(
        shown.contains(&en_with(keys::WEB_SECRET_USER_PROTECTED, &[]))
            && !shown.contains("name=\"secret\""),
        "the dialog explains instead of asking: {shown}"
    );
    assert_eq!(
        fixture.router(ROUTER)?.request_count(),
        before,
        "the router heard nothing"
    );
    for body in [&differ, &asked, &protected] {
        assert!(
            !body.contains(&typed) && !body.contains(&other),
            "never echoed"
        );
    }
    assert_eq!(
        fixture.outcomes("web.router_user_password")?,
        [
            "validation_failed",
            "confirmation_required",
            "protected_account"
        ],
        "each refusal audited"
    );
    Ok(())
}

#[tokio::test]
async fn an_operator_sees_no_password_control_and_is_refused() -> TestResult {
    let fixture = setup::fixture().await?;
    let admin = fixture.login("admin").await?;
    let named = [("name", "alice"), ("confirm", "yes")];
    let (add_status, _) = post(&fixture, &admin, ("/ui/r/prod-1/system/users", &named)).await?;
    assert_eq!(add_status, StatusCode::OK, "added");
    let operator = fixture.login("operator").await?;
    let page = text(fixture.get("/ui/r/prod-1/system/users", &operator).await?).await?;
    assert!(
        page.contains("alice") && !page.contains("users/password"),
        "no control: {page}"
    );
    let secret = dummy("alice", 5);
    let fields = [
        ("confirm", "yes"),
        ("secret", secret.as_str()),
        ("secret_again", secret.as_str()),
    ];
    let (refused_status, _) = post(&fixture, &operator, (ALICE, &fields)).await?;
    assert_eq!(refused_status, StatusCode::FORBIDDEN, "ManageUsers needed");
    assert_eq!(
        fixture.get(ALICE, &operator).await?.status(),
        StatusCode::FORBIDDEN,
        "no dialog"
    );
    assert_eq!(digest(&fixture, "alice")?, None, "nothing written");
    Ok(())
}
