//! A router edit whose profile update fails leaves every sealed record as it was.

use std::fs;

use axum::http::StatusCode;
use kcc_testkit::{DEFAULT_LOGIN, DEFAULT_PASSWORD, model::Profile};

use crate::{
    router_credentials::{dummy, origin, sealed},
    support::{outcome::TestResult, page::form},
    tests::{ROUTER_LOGIN, ROUTER_SECRET, fleet},
};

/// SEC1-09, W1-05: an update that fails after sealing restores every sealed record byte
/// for byte, so the stored profile still signs in with its old secrets.
#[tokio::test]
async fn a_failed_profile_write_restores_every_sealed_record() -> TestResult {
    let fixture = fleet(&[("home", Profile::default())]).await?;
    let browser = fixture.login("admin").await?;
    let url = origin(&fixture, "home")?;
    let save = form(&[
        ("router", "home"),
        ("url", &url),
        ("login", DEFAULT_LOGIN),
        ("password", DEFAULT_PASSWORD),
        ("tls", "verify"),
        ("read_login", ROUTER_LOGIN),
        ("read_password", ROUTER_SECRET),
    ]);
    let saved = fixture
        .post("/ui/routers/home/edit", &browser, &save)
        .await?;
    assert_eq!(saved.status(), StatusCode::OK, "precondition");
    let names = ["home.sealed", "home.token.sealed", "home.read.sealed"];
    let snapshot = || {
        names
            .iter()
            .map(|name| fs::read(sealed(&fixture, name)).ok())
            .collect::<Vec<_>>()
    };
    let before = snapshot();
    let profile = fixture.registry().get("home")?.profile;
    fs::create_dir_all(fixture.state_dir().join(".routers.json.tmp/held"))?;
    let body = form(&[
        ("router", "home"),
        ("url", &url),
        ("login", DEFAULT_LOGIN),
        ("password", &dummy("password")?),
        ("tls", "verify"),
        ("read_login", ROUTER_LOGIN),
        ("read_password", &dummy("reader")?),
    ]);

    let response = fixture
        .post("/ui/routers/home/edit", &browser, &body)
        .await?;

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(snapshot(), before, "sealed records restored");
    assert_eq!(fixture.registry().get("home")?.profile, profile);
    assert!(
        fixture.registry().test_connection(&profile).await.is_ok(),
        "the old password signs in"
    );
    assert!(
        fixture.registry().poll_info("home").await.is_ok(),
        "the old read-only password signs in"
    );
    Ok(())
}
