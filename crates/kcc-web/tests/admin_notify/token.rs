//! The bot token: sealed when saved, refused when malformed, removed after a
//! confirmation, and never rendered, stored in the clear or audited.

use axum::http::StatusCode;
use kcc_app::notify_store::token::NotifySecrets;
use kcc_i18n::keys;
use secrecy::{ExposeSecret as _, SecretString};
use serde_json::json;

use crate::{
    fixture::Notify,
    support::{
        build::master_key,
        outcome::TestResult,
        page::{en, text},
    },
};

const TOKEN: &str = "/ui/admin/notifications/token";
const CLEAR: &str = "/ui/admin/notifications/token/clear";

/// A well-formed bot token, built at run time.
fn bot_token() -> String {
    format!("{}:{}", 7_u64.pow(11), "kQ9_z-Lm".repeat(5))
}

/// Regression (todo 11): a saved token is sealed and never shown, stored clear or audited.
///
/// Neither the answer, the page, the audit log nor any file in the state directory holds
/// its bytes; the audit entry says only that the credential changed.
#[tokio::test]
async fn a_saved_token_is_sealed_and_never_shown_or_audited() -> TestResult {
    let fixture = Notify::build(None).await?;
    let admin = fixture.login("admin").await?;
    let token = bot_token();
    let secret_part = token
        .split_once(':')
        .map(|(_, secret)| secret)
        .ok_or("shape")?;
    let saved = fixture.post(TOKEN, &admin, &[("token", &token)]).await?;
    assert_eq!(saved.status(), StatusCode::OK, "saved");
    let answer = text(saved).await?;
    assert!(
        answer.contains(&en(keys::WEB_ADMIN_NOTIFY_TOKEN_SAVED)),
        "token saved"
    );
    let page = fixture.html("/ui/admin/notifications", &admin).await?;
    for (name, html) in [("answer", &answer), ("page", &page)] {
        assert!(!html.contains(secret_part), "{name} holds no token bytes");
    }
    assert!(
        page.contains(&en(keys::WEB_ADMIN_NOTIFY_TOKEN_SET)),
        "the page says a token is set"
    );
    let stored = NotifySecrets::token(fixture.store(), &master_key())?.ok_or("no token")?;
    assert_eq!(stored.expose_secret(), token, "the sealed token opens");
    let entries = fixture.audited("web.notify_token").await?;
    let params: Vec<_> = entries.iter().map(|entry| &entry.params_redacted).collect();
    assert_eq!(
        params,
        [&json!({"credential_changed": true})],
        "one change audited"
    );
    assert!(!fixture.state_holds(secret_part)?, "no clear token at rest");
    Ok(())
}

/// Regression (todo 11): a malformed or empty token is refused naming the field only,
/// never echoing the value, and nothing is stored or audited.
#[tokio::test]
async fn an_invalid_token_is_refused_naming_the_field_only() -> TestResult {
    let fixture = Notify::build(None).await?;
    let admin = fixture.login("admin").await?;
    let malformed = format!("{}:{}", 42_u8, "short".repeat(2));
    for (value, message) in [
        (malformed.as_str(), keys::WEB_ADMIN_NOTIFY_ERROR_TOKEN),
        ("", keys::WEB_ADMIN_NOTIFY_ERROR_TOKEN_EMPTY),
    ] {
        let refused = fixture.post(TOKEN, &admin, &[("token", value)]).await?;
        assert_eq!(
            refused.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "refused"
        );
        let html = text(refused).await?;
        assert!(html.contains(&en(message)), "the field's error");
        assert!(
            html.contains("id=\"notify-token-error\""),
            "named at the token field"
        );
        assert!(
            value.is_empty() || !html.contains(value),
            "the value is not echoed"
        );
    }
    assert!(
        NotifySecrets::token(fixture.store(), &master_key())?.is_none(),
        "nothing stored"
    );
    assert!(
        fixture.audited("web.notify_token").await?.is_empty(),
        "nothing audited"
    );
    Ok(())
}

/// Regression (todo 11): removing the token asks first; the confirmed removal deletes the
/// sealed token and audits that the credential was cleared.
#[tokio::test]
async fn removing_the_token_asks_first() -> TestResult {
    let fixture = Notify::build(None).await?;
    let admin = fixture.login("admin").await?;
    NotifySecrets::set_token(
        fixture.store(),
        &master_key(),
        &SecretString::from(bot_token()),
    )?;
    let dialog = fixture.get(CLEAR, &admin).await?;
    assert_eq!(dialog.status(), StatusCode::OK, "the dialog");
    let asked = text(dialog).await?;
    assert!(
        asked.contains(&en(keys::WEB_ADMIN_NOTIFY_TOKEN_CLEAR_TEXT)),
        "it asks"
    );
    assert!(
        asked.contains("name=\"confirm\" value=\"yes\""),
        "it confirms"
    );
    let unconfirmed = fixture.post(CLEAR, &admin, &[]).await?;
    assert_eq!(unconfirmed.status(), StatusCode::OK, "asked again");
    assert!(
        NotifySecrets::token(fixture.store(), &master_key())?.is_some(),
        "kept without a confirmation"
    );
    let cleared = fixture.post(CLEAR, &admin, &[("confirm", "yes")]).await?;
    assert_eq!(cleared.status(), StatusCode::OK, "removed");
    assert!(
        text(cleared)
            .await?
            .contains(&en(keys::WEB_ADMIN_NOTIFY_TOKEN_CLEARED)),
        "token removed"
    );
    assert!(
        NotifySecrets::token(fixture.store(), &master_key())?.is_none(),
        "the sealed token is gone"
    );
    let entries = fixture.audited("web.notify_token").await?;
    let params: Vec<_> = entries.iter().map(|entry| &entry.params_redacted).collect();
    assert_eq!(
        params,
        [&json!({"credential_cleared": true})],
        "one removal audited"
    );
    Ok(())
}
