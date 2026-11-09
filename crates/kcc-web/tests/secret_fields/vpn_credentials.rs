//! VPN client credentials (an L2TP/IPsec connection's password and IPsec key) and the VPN
//! servers' IKE key and account password; a viewer gets none of them.

use axum::http::StatusCode;
use kcc_i18n::keys;

use crate::{
    ROUTER, TraceCapture, assert_native_post, dummy, en, nowhere, stored,
    support::{Browser, Fixture, TestResult, text},
};

/// Posts the new value `secret` twice with `fields` to `path` as `browser`.
async fn set(
    fixture: &Fixture,
    browser: &Browser,
    (path, fields, secret): (&str, &[(&str, &str)], &str),
) -> TestResult<(StatusCode, String)> {
    let mut pairs = fields.to_vec();
    pairs.extend([("secret", secret), ("secret_again", secret)]);
    let response = fixture.post(path, browser, &pairs).await?;
    Ok((response.status(), text(response).await?))
}

/// An L2TP/IPsec connection with a password set on the router itself.
async fn seeded() -> TestResult<Fixture> {
    let fixture = Fixture::new().await?;
    let client = fixture.registry().client(ROUTER).await?;
    let first = dummy("seed", 8);
    drop(
        client
            .parse(&format!("interface L2TP0 authentication password {first}"))
            .await?,
    );
    Ok(fixture)
}

#[tokio::test]
async fn client_credentials_reach_the_router_and_nothing_else() -> TestResult {
    let trace = TraceCapture::install();
    let fixture = seeded().await?;
    let operator = fixture.login("operator").await?;
    let page = text(fixture.get("/ui/r/prod-1/vpn", &operator).await?).await?;
    for action in [
        "/ui/r/prod-1/vpn/credential?kind=password&#38;name=L2TP0",
        "/ui/r/prod-1/vpn/credential?kind=ipsec&#38;name=L2TP0",
    ] {
        assert!(page.contains(action), "the row offers {action}: {page}");
    }
    let config = |current: &Fixture, prefix: &str| -> TestResult<Option<String>> {
        let lines = current.handle(ROUTER)?.running_config_text();
        Ok(stored(&lines, "interface L2TP0", prefix))
    };
    let seeded_password = config(&fixture, "authentication password ")?;
    let (password, psk) = (dummy("l2tp", 1), dummy("ipsec", 2));
    let mut served = vec![page];
    for (kind, secret, prefix) in [
        ("password", &password, "authentication password "),
        ("ipsec", &psk, "ipsec preshared-key "),
    ] {
        let path = format!("/ui/r/prod-1/vpn/credential?kind={kind}&name=L2TP0");
        served.push(text(fixture.get(&path, &operator).await?).await?);
        let (status, answer) = set(&fixture, &operator, (&path, &[], secret)).await?;
        assert_eq!(status, StatusCode::OK, "{kind} written: {answer}");
        assert!(answer.contains("id=\"unsaved-badge\""), "{kind}: unsaved");
        let found = config(&fixture, prefix)?.ok_or("not stored")?;
        assert!(found.starts_with("ns3 "), "{kind} stored encoded");
        served.push(answer);
    }
    assert_ne!(
        config(&fixture, "authentication password ")?,
        seeded_password,
        "a new password"
    );
    for path in [
        "/ui/r/prod-1/vpn/credential?kind=password&name=L2TP9",
        "/ui/r/prod-1/vpn/credential?kind=xauth&name=office",
    ] {
        let (status, _) = set(&fixture, &operator, (path, &[], &password)).await?;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}: not on the router");
    }
    let config_now = fixture.handle(ROUTER)?.running_config_text();
    assert!(
        !config_now.contains("L2TP9") && !config_now.contains("xauth"),
        "nothing written"
    );
    for secret in [&password, &psk] {
        nowhere(secret, &served, (&fixture, &trace))?;
    }
    Ok(())
}

#[tokio::test]
async fn server_credentials_reach_the_router_and_nothing_else() -> TestResult {
    let trace = TraceCapture::install();
    let fixture = Fixture::new().await?;
    let admin = fixture.login("admin").await?;
    let named = [("name", "bob"), ("confirm", "yes")];
    let added = fixture
        .post("/ui/r/prod-1/system/users", &admin, &named)
        .await?;
    assert_eq!(added.status(), StatusCode::OK, "bob added");
    let page = text(fixture.get("/ui/r/prod-1/vpn/servers", &admin).await?).await?;
    for action in [
        "/ui/r/prod-1/vpn/server/psk",
        "/ui/r/prod-1/vpn/server/password",
    ] {
        assert!(page.contains(action), "the servers tab offers {action}");
    }
    let psk = dummy("ike", 1);
    let key = [("key", "VirtualIPServer")];
    let (status, keyed) = set(
        &fixture,
        &admin,
        ("/ui/r/prod-1/vpn/server/psk", &key, &psk),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "IKE key written: {keyed}");
    let keyed_config = fixture.handle(ROUTER)?.running_config_text();
    assert!(
        keyed_config.contains("crypto ike key VirtualIPServer ns3 "),
        "stored encoded"
    );
    let dialog = text(
        fixture
            .get("/ui/r/prod-1/vpn/server/password", &admin)
            .await?,
    )
    .await?;
    assert_native_post(&dialog)?;
    assert!(
        dialog.contains("<option value=\"bob\"") && !dialog.contains("<option value=\"admin\""),
        "the accounts kcc may change: {dialog}"
    );
    let password = dummy("bob", 2);
    let account = [("account", "bob"), ("confirm", "yes")];
    let path = "/ui/r/prod-1/vpn/server/password";
    let (changed_status, changed) = set(&fixture, &admin, (path, &account, &password)).await?;
    assert_eq!(
        changed_status,
        StatusCode::OK,
        "account password written: {changed}"
    );
    let user_config = fixture.handle(ROUTER)?.running_config_text();
    let digest = stored(&user_config, "user bob", "password md5 ").ok_or("no digest")?;
    assert_eq!(digest.len(), 32, "a digest of the expected length");
    let before = fixture.handle(ROUTER)?.request_count();
    let login = [("account", "admin"), ("confirm", "yes")];
    let (refused_status, refused) = set(&fixture, &admin, (path, &login, &password)).await?;
    assert_eq!(
        refused_status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "kcc's own login"
    );
    assert!(
        refused.contains(&en(keys::WEB_SECRET_USER_PROTECTED, &[])),
        "localized"
    );
    assert_eq!(
        fixture.handle(ROUTER)?.request_count(),
        before,
        "nothing sent"
    );
    for secret in [&psk, &password] {
        let served = [
            page.clone(),
            keyed.clone(),
            dialog.clone(),
            changed.clone(),
            refused.clone(),
        ];
        nowhere(secret, &served, (&fixture, &trace))?;
    }
    Ok(())
}

#[tokio::test]
async fn a_viewer_sees_no_secret_control_and_is_refused() -> TestResult {
    let fixture = seeded().await?;
    let viewer = fixture.login("viewer").await?;
    for page in [
        "/ui/r/prod-1/vpn",
        "/ui/r/prod-1/vpn/servers",
        "/ui/r/prod-1/wifi/settings?name=WifiMaster1%2FAccessPoint0",
        "/ui/r/prod-1/internet/settings?name=L2TP0",
    ] {
        let shown = text(fixture.get(page, &viewer).await?).await?;
        for control in [
            "vpn/credential",
            "vpn/server/",
            "wifi/psk",
            "internet/password",
        ] {
            assert!(
                !shown.contains(control),
                "{page} offers {control} to a viewer"
            );
        }
    }
    let secret = dummy("viewer", 1);
    let before = fixture.handle(ROUTER)?.request_count();
    for path in [
        "/ui/r/prod-1/wifi/psk?name=WifiMaster1%2FAccessPoint0",
        "/ui/r/prod-1/internet/password?name=L2TP0",
        "/ui/r/prod-1/vpn/credential?kind=password&name=L2TP0",
        "/ui/r/prod-1/vpn/server/psk",
        "/ui/r/prod-1/vpn/server/password",
        "/ui/r/prod-1/system/users/password?name=bob",
    ] {
        assert_eq!(
            fixture.get(path, &viewer).await?.status(),
            StatusCode::FORBIDDEN,
            "{path}"
        );
        let (status, _) = set(
            &fixture,
            &viewer,
            (path, &[("key", "VirtualIPServer")], &secret),
        )
        .await?;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path}");
    }
    let scoped = fixture.login("scoped").await?;
    let path = "/ui/r/prod-1/wifi/psk?name=WifiMaster1%2FAccessPoint0";
    let (status, _) = set(&fixture, &scoped, (path, &[], &secret)).await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "outside the role's routers");
    assert_eq!(
        fixture.handle(ROUTER)?.request_count(),
        before,
        "the router heard nothing"
    );
    Ok(())
}
