//! What the VPN routes refuse to touch: an interface that is not a VPN connection, and
//! the name of a live connection for a new one.

use axum::http::StatusCode;
use kcc_i18n::{keys, locale::Locale};

use crate::{
    form, key, said,
    support::{Fixture, TestResult, text},
    upload::{sign_in, upload},
};

/// The connections tab.
const PAGE: &str = "/ui/r/home/vpn";

#[tokio::test]
async fn connection_routes_touch_only_vpn_connections() -> TestResult {
    let fixture = Fixture::new().await?;
    let admin = fixture.login("admin").await?;
    let before = fixture.handle().running_config_text();
    let down = form(&[("tunnel", "Bridge0"), ("enabled", "off")]);
    let switched = fixture
        .post(&format!("{PAGE}/state"), &admin, &down)
        .await?;
    assert_eq!(
        switched.status(),
        StatusCode::NOT_FOUND,
        "not a VPN connection"
    );
    let typed = form(&[
        ("object", "Bridge0"),
        ("confirm", "yes"),
        ("confirm_name", "Bridge0"),
    ]);
    let deleted = fixture
        .post(&format!("{PAGE}/delete"), &admin, &typed)
        .await?;
    assert_eq!(deleted.status(), StatusCode::NOT_FOUND, "nor deleted");
    assert_eq!(
        fixture.handle().running_config_text(),
        before,
        "the router's configuration is untouched"
    );
    let audit = fixture.audit()?;
    for action in ["web.vpn_state", "web.vpn_delete"] {
        assert!(
            audit
                .iter()
                .any(|entry| entry.action == action && entry.outcome == "validation_failed"),
            "{action} refusal audited"
        );
    }
    Ok(())
}

#[tokio::test]
async fn a_new_connection_never_reuses_a_live_name() -> TestResult {
    let fixture = Fixture::new().await?;
    let operator = fixture.login("operator").await?;
    let create = form(&[("name", "Wireguard3")]);
    let first = fixture
        .post(&format!("{PAGE}/form/create"), &operator, &create)
        .await?;
    assert_eq!(first.status(), StatusCode::OK, "created");
    let again = fixture
        .post(&format!("{PAGE}/form/create"), &operator, &create)
        .await?;
    assert_eq!(
        again.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "the name is taken"
    );
    let taken = said(Locale::En, keys::WEB_VPN_ERROR_NAME_TAKEN);
    assert!(text(again).await?.contains(&taken), "said under the name");
    let signed = sign_in(&fixture, "operator").await?;
    let conf = format!(
        "[Interface]\nListenPort = 51820\n\n[Peer]\nPublicKey = {}\n",
        key(4)
    );
    let imported = upload(&fixture, &signed, ("Wireguard3", conf.as_bytes(), true)).await?;
    assert_eq!(
        imported.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "nor imported over"
    );
    assert!(
        text(imported).await?.contains(&taken),
        "the import says so too"
    );
    Ok(())
}
