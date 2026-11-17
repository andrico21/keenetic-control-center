//! The password of a PPP internet connection.

use core::net::Ipv4Addr;

use axum::http::StatusCode;
use kcc_i18n::keys;
use kcc_testkit::{FakeRouter, model::Profile};
use serde_json::json;

use crate::{
    ROUTER, TraceCapture, dummy, nowhere, setup, stored,
    support::{
        asked::commands_since,
        outcome::TestResult,
        page::{assert_native_post, en_with, text},
        web::Fixture,
    },
};

/// The connection's dialog and write.
const DIALOG: &str = "/ui/r/prod-1/internet/password?name=PPPoE0";

/// The stored password of `PPPoE0`: `ns3 <blob>`.
fn password(fixture: &Fixture) -> TestResult<Option<String>> {
    let config = fixture.router(ROUTER)?.running_config_text();
    Ok(stored(
        &config,
        "interface PPPoE0",
        "authentication password ",
    ))
}

/// A PPPoE connection with a password set on the router itself.
async fn seeded() -> TestResult<Fixture> {
    let fixture = setup::fixture().await?;
    let client = fixture.registry().client(ROUTER).await?;
    let first = dummy("seed", 9);
    drop(
        client
            .parse(&format!("interface PPPoE0 authentication password {first}"))
            .await?,
    );
    Ok(fixture)
}

#[tokio::test]
async fn a_connection_password_reaches_the_router_and_nothing_else() -> TestResult {
    let trace = TraceCapture::install();
    let fixture = seeded().await?;
    let operator = fixture.login("operator").await?;
    let settings = text(
        fixture
            .get("/ui/r/prod-1/internet/settings?name=PPPoE0", &operator)
            .await?,
    )
    .await?;
    assert!(
        settings.contains(&format!("hx-get=\"{DIALOG}\"")),
        "Edit beside the password: {settings}"
    );
    let dialog = text(fixture.get(DIALOG, &operator).await?).await?;
    assert_native_post(&dialog)?;
    assert!(
        dialog.contains("name=\"secret\" type=\"password\" value=\"\""),
        "write-only: {dialog}"
    );
    let before = password(&fixture)?.ok_or("no seeded password")?;
    let secret = dummy("wan", 1);
    let response = fixture
        .post_form(
            DIALOG,
            &operator,
            &[("secret", &secret), ("secret_again", &secret)],
        )
        .await?;
    let status = response.status();
    let answer = text(response).await?;
    assert_eq!(status, StatusCode::OK, "written: {answer}");
    let what = en_with(keys::WEB_INTERNET_PASSWORD, &[]);
    assert!(
        answer.contains(&en_with(keys::WEB_SECRET_CHANGED, &[("what", &what)])),
        "the read-back's verdict: {answer}"
    );
    let written = password(&fixture)?.ok_or("no password stored")?;
    assert!(written.starts_with("ns3 "), "encoded");
    assert_ne!(written, before, "a new value");
    let empty = fixture
        .post_form(DIALOG, &operator, &[("secret", ""), ("secret_again", "")])
        .await?;
    assert_eq!(empty.status(), StatusCode::OK, "nothing to send");
    let kept = text(empty).await?;
    assert_eq!(
        password(&fixture)?,
        Some(written),
        "the stored password stays"
    );
    nowhere(
        &secret,
        &[settings, dialog, answer, kept],
        (&fixture, &trace),
    )?;
    assert_eq!(
        fixture.outcomes("web.internet_password")?,
        ["success", "unchanged"],
        "audited"
    );
    Ok(())
}

#[tokio::test]
async fn only_ppp_connections_take_a_password() -> TestResult {
    let fixture = seeded().await?;
    let operator = fixture.login("operator").await?;
    let ipoe = text(
        fixture
            .get("/ui/r/prod-1/internet/settings?name=ISP", &operator)
            .await?,
    )
    .await?;
    assert!(!ipoe.contains("internet/password"), "IPoE has no password");
    let secret = dummy("wan", 2);
    let refused = fixture
        .post_form(
            "/ui/r/prod-1/internet/password?name=ISP",
            &operator,
            &[("secret", &secret), ("secret_again", &secret)],
        )
        .await?;
    assert_eq!(
        refused.status(),
        StatusCode::NOT_FOUND,
        "not a PPP connection"
    );
    let config = fixture.router(ROUTER)?.running_config_text();
    assert_eq!(
        stored(&config, "interface ISP", "authentication password "),
        None,
        "nothing written"
    );
    Ok(())
}

/// The dialog of `PPPoE0` on the single router of [`Fixture::with_router`].
const OWN_DIALOG: &str = "/ui/r/home/internet/password?name=PPPoE0";

/// C-06: the management connection's password is confirmed in its own dialog.
///
/// The kit's dialog would send the request again without the typed password. The dialog
/// explains the fail-safe timer, an unconfirmed Apply sends nothing, and the confirmed one
/// runs inside the timer.
#[tokio::test]
async fn the_management_connection_password_is_confirmed_in_its_dialog() -> TestResult {
    let peer = Ipv4Addr::LOCALHOST.to_string();
    let fake = FakeRouter::builder(Profile::default())
        .show_fixture(
            "interface",
            json!({"PPPoE0":{"id":"PPPoE0","type":"PPPoE","address":peer,"mask":"255.255.255.255"}}),
        )
        .build()?;
    let fixture = Fixture::with_router(fake).await?;
    let admin = fixture.login("admin").await?;
    let dialog = text(fixture.get(OWN_DIALOG, &admin).await?).await?;
    assert!(
        dialog.contains("<input type=\"hidden\" name=\"confirm\" value=\"yes\">"),
        "Apply confirms in the dialog: {dialog}"
    );
    let secret = dummy("wan", 3);
    let typed = [
        ("secret", secret.as_str()),
        ("secret_again", secret.as_str()),
    ];
    let unset = fixture.handle().running_config_text();
    assert_eq!(
        stored(&unset, "interface PPPoE0", "authentication password "),
        None
    );

    let before = fixture.handle().request_log().len();
    let unconfirmed = fixture.post_form(OWN_DIALOG, &admin, &typed).await?;
    let status = unconfirmed.status();
    let asked = text(unconfirmed).await?;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{asked}");
    assert!(
        asked.contains(&en_with(keys::WEB_SECRET_CONFIRM, &[])),
        "says so: {asked}"
    );
    assert_eq!(commands_since(&fixture, before), Vec::<String>::new());

    let confirmed = [("confirm", "yes"), typed[0], typed[1]];
    let response = fixture.post_form(OWN_DIALOG, &admin, &confirmed).await?;

    assert_eq!(response.status(), StatusCode::OK);
    let sent = commands_since(&fixture, before);
    assert_eq!(
        sent.first().map(String::as_str),
        Some("system configuration fail-safe timer reboot 300"),
        "armed first: {sent:?}"
    );
    assert_eq!(
        sent.last().map(String::as_str),
        Some("no system configuration fail-safe timer"),
        "disarmed last: {sent:?}"
    );
    let config = fixture.handle().running_config_text();
    assert!(
        stored(&config, "interface PPPoE0", "authentication password ").is_some(),
        "the password reached the router: {config}"
    );
    Ok(())
}
