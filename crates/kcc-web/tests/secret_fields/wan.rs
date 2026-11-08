//! The password of a PPP internet connection.

use axum::http::StatusCode;
use kcc_i18n::keys;

use crate::{
    ROUTER, TraceCapture, dummy, en, nowhere, stored,
    support::{Fixture, TestResult, text},
};

/// The connection's dialog and write.
const DIALOG: &str = "/ui/r/prod-1/internet/password?name=PPPoE0";

/// The stored password of `PPPoE0`: `ns3 <blob>`.
fn password(fixture: &Fixture) -> TestResult<Option<String>> {
    let config = fixture.handle(ROUTER)?.running_config_text();
    Ok(stored(
        &config,
        "interface PPPoE0",
        "authentication password ",
    ))
}

/// A PPPoE connection with a password set on the router itself.
async fn seeded() -> TestResult<Fixture> {
    let fixture = Fixture::new().await?;
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
    assert!(
        dialog.contains("name=\"secret\" type=\"password\" value=\"\""),
        "write-only: {dialog}"
    );
    let before = password(&fixture)?.ok_or("no seeded password")?;
    let secret = dummy("wan", 1);
    let response = fixture
        .post(
            DIALOG,
            &operator,
            &[("secret", &secret), ("secret_again", &secret)],
        )
        .await?;
    let status = response.status();
    let answer = text(response).await?;
    assert_eq!(status, StatusCode::OK, "written: {answer}");
    let what = en(keys::WEB_INTERNET_PASSWORD, &[]);
    assert!(
        answer.contains(&en(keys::WEB_SECRET_DONE, &[("what", &what)])),
        "the read-back's verdict: {answer}"
    );
    let written = password(&fixture)?.ok_or("no password stored")?;
    assert!(written.starts_with("ns3 "), "encoded");
    assert_ne!(written, before, "a new value");
    let empty = fixture
        .post(DIALOG, &operator, &[("secret", ""), ("secret_again", "")])
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
        .post(
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
    let config = fixture.handle(ROUTER)?.running_config_text();
    assert_eq!(
        stored(&config, "interface ISP", "authentication password "),
        None,
        "nothing written"
    );
    Ok(())
}
