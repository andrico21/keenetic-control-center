//! Editing a router profile: a changed credential binding needs the password, a tag edit
//! keeps the stored credential, and moving the endpoint drops the poll credentials.

use core::error::Error;

use axum::http::StatusCode;
use kcc_app::registry::ManagedRouterProfile;
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_testkit::{DEFAULT_LOGIN, DEFAULT_PASSWORD, model::Profile};

use crate::{
    support::{build::admin, outcome::TestResult, page::text, web::Fixture},
    tests::{ROUTER_LOGIN, ROUTER_SECRET, fleet},
};

/// An empty password cannot move a stored credential to another endpoint, and the
/// rejected form leaves both the stored profile and the foreign router untouched.
#[tokio::test]
async fn editing_a_credential_binding_without_a_password_is_refused_atomically() -> TestResult {
    let fixture = fleet(&[
        ("home", Profile::default()),
        ("foreign", Profile::default()),
    ])
    .await?;
    let browser = fixture.login("router-manager").await?;
    let original = fixture.registry().get("home")?.profile;
    let foreign_url = fixture.registry().get("foreign")?.profile.url;
    let foreign = fixture.router("foreign")?;
    let before = foreign.request_log().len();
    let encoded_url = foreign_url
        .as_str()
        .trim_end_matches('/')
        .replace(':', "%3A")
        .replace('/', "%2F");
    let form = format!(
        "router=home&url={encoded_url}&login={DEFAULT_LOGIN}&password=&tls=verify&tags=moved"
    );

    let response = fixture
        .post("/ui/routers/home/edit", &browser, &form)
        .await?;

    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let page = text(response).await?;
    assert!(
        page.contains(&tr(Locale::En, keys::WEB_ROUTER_ERROR_PASSWORD, None)),
        "the password field names the required credential"
    );
    let stored = fixture.registry().get("home")?.profile;
    assert_eq!(stored.url, original.url, "endpoint remains unchanged");
    assert_eq!(stored.tags, original.tags, "the whole edit is atomic");
    assert_eq!(
        foreign.request_log().len(),
        before,
        "the foreign endpoint receives no request"
    );
    Ok(())
}

/// A login-only or TLS-mode-only edit also moves the credential binding, so an empty
/// password refuses it and the stored profile stays as it was.
#[tokio::test]
async fn editing_the_login_or_tls_mode_without_a_password_is_refused() -> TestResult {
    let fixture = fleet(&[("home", Profile::default())]).await?;
    let browser = fixture.login("router-manager").await?;
    let original = fixture.registry().get("home")?.profile;
    let encoded_url = original
        .url
        .as_str()
        .trim_end_matches('/')
        .replace(':', "%3A")
        .replace('/', "%2F");
    let pin = "ab".repeat(32);
    for binding in [
        format!("login={DEFAULT_LOGIN}&tls=pin&tls_pin={pin}"),
        format!("login={DEFAULT_LOGIN}2&tls=verify"),
    ] {
        let form = format!("router=home&url={encoded_url}&{binding}&password=&tags=moved");

        let response = fixture
            .post("/ui/routers/home/edit", &browser, &form)
            .await?;

        assert_eq!(
            response.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "{binding}"
        );
        let page = text(response).await?;
        assert!(
            page.contains(&tr(Locale::En, keys::WEB_ROUTER_ERROR_PASSWORD, None)),
            "{binding}: the password field names the required credential"
        );
        let stored = fixture.registry().get("home")?.profile;
        assert_eq!(stored.login, original.login, "{binding}: login unchanged");
        assert_eq!(stored.tls, original.tls, "{binding}: TLS mode unchanged");
        assert_eq!(stored.tags, original.tags, "{binding}: the edit is atomic");
        assert_eq!(
            stored.password_file, original.password_file,
            "{binding}: credential unchanged"
        );
    }
    Ok(())
}

/// Non-binding metadata changes keep the existing credential when the password is empty.
#[tokio::test]
async fn editing_tags_without_a_password_keeps_the_stored_credential() -> TestResult {
    let fixture = fleet(&[("home", Profile::default())]).await?;
    let browser = fixture.login("router-manager").await?;
    let original = fixture.registry().get("home")?.profile;
    let encoded_url = original
        .url
        .as_str()
        .trim_end_matches('/')
        .replace(':', "%3A")
        .replace('/', "%2F");
    let form = format!(
        "router=home&url={encoded_url}&login={DEFAULT_LOGIN}&password=&tls=verify&tags=trusted"
    );

    let response = fixture
        .post("/ui/routers/home/edit", &browser, &form)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let stored = fixture.registry().get("home")?.profile;
    assert_eq!(stored.url, original.url, "endpoint remains bound");
    assert_eq!(
        stored.password_file, original.password_file,
        "credential remains bound"
    );
    assert_eq!(stored.tags, ["trusted"], "metadata is updated");
    Ok(())
}

/// A typed password authorizes moving the profile and credential to a new endpoint.
#[tokio::test]
async fn editing_an_endpoint_with_a_password_rebinds_the_credential() -> TestResult {
    let fixture = fleet(&[
        ("home", Profile::default()),
        ("foreign", Profile::default()),
    ])
    .await?;
    let browser = fixture.login("router-manager").await?;
    let foreign_url = fixture.registry().get("foreign")?.profile.url;
    let encoded_url = foreign_url
        .as_str()
        .trim_end_matches('/')
        .replace(':', "%3A")
        .replace('/', "%2F");
    let form = format!(
        "router=home&url={encoded_url}&login={DEFAULT_LOGIN}&password={DEFAULT_PASSWORD}&tls=verify&tags="
    );

    let response = fixture
        .post("/ui/routers/home/edit", &browser, &form)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let stored = fixture.registry().get("home")?.profile;
    assert_eq!(stored.url, foreign_url, "endpoint is updated");
    assert_eq!(
        fixture
            .registry()
            .test_connection(&stored)
            .await?
            .version
            .model,
        Some("Keenetic Ultra".to_owned()),
        "the replacement credential authenticates at the new endpoint"
    );
    Ok(())
}

/// `ManageRouters` without `Read` cannot edit a profile of a router the role cannot see.
#[tokio::test]
async fn editing_a_profile_without_read_is_refused_without_a_request() -> TestResult {
    let fixture = fleet(&[("home", Profile::default())]).await?;
    let browser = fixture.login("manage-only").await?;
    let original = fixture.registry().get("home")?.profile;
    let home = fixture.router("home")?;
    let before = home.request_log().len();
    let encoded_url = original
        .url
        .as_str()
        .trim_end_matches('/')
        .replace(':', "%3A")
        .replace('/', "%2F");
    let form = format!(
        "router=home&url={encoded_url}&login={DEFAULT_LOGIN}&password={DEFAULT_PASSWORD}&tls=verify&tags=hijacked"
    );

    let response = fixture
        .post("/ui/routers/home/edit", &browser, &form)
        .await?;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        fixture.registry().get("home")?.profile,
        original,
        "profile unchanged"
    );
    assert_eq!(
        home.request_log().len(),
        before,
        "the router receives no request"
    );
    Ok(())
}

/// Stores read-only poll credentials on `id` and returns the stored profile.
async fn with_read_credentials(
    fixture: &Fixture,
    id: &str,
) -> Result<ManagedRouterProfile, Box<dyn Error + Send + Sync>> {
    let read_file =
        kcc_testkit::write_secret_file(&fixture.directory(), "read-password", ROUTER_SECRET)?;
    let mut profile = fixture.registry().get(id)?.profile;
    profile.read_login = Some(ROUTER_LOGIN.to_owned());
    profile.read_password_file = Some(read_file);
    fixture.registry().update(&admin()?, profile).await?;
    Ok(fixture.registry().get(id)?.profile)
}

/// Moving the endpoint drops the stored read-only poll credentials, so they are never
/// sent to an endpoint they were not stored for.
#[tokio::test]
async fn moving_the_endpoint_drops_the_read_only_poll_credentials() -> TestResult {
    let fixture = fleet(&[
        ("home", Profile::default()),
        ("foreign", Profile::default()),
    ])
    .await?;
    let browser = fixture.login("router-manager").await?;
    let original = with_read_credentials(&fixture, "home").await?;
    assert!(
        original.read_login.is_some(),
        "precondition: read login stored"
    );
    let foreign_url = fixture.registry().get("foreign")?.profile.url;
    let encoded_url = foreign_url
        .as_str()
        .trim_end_matches('/')
        .replace(':', "%3A")
        .replace('/', "%2F");
    let form = format!(
        "router=home&url={encoded_url}&login={DEFAULT_LOGIN}&password={DEFAULT_PASSWORD}&tls=verify&tags="
    );

    let response = fixture
        .post("/ui/routers/home/edit", &browser, &form)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let stored = fixture.registry().get("home")?.profile;
    assert_eq!(stored.url, foreign_url, "endpoint is updated");
    assert_eq!(stored.read_login, None, "read login dropped");
    assert_eq!(
        stored.read_password_file, None,
        "read password file dropped"
    );
    Ok(())
}

/// A metadata-only edit keeps the stored read-only poll credentials.
#[tokio::test]
async fn editing_tags_keeps_the_read_only_poll_credentials() -> TestResult {
    let fixture = fleet(&[("home", Profile::default())]).await?;
    let browser = fixture.login("router-manager").await?;
    let original = with_read_credentials(&fixture, "home").await?;
    let encoded_url = original
        .url
        .as_str()
        .trim_end_matches('/')
        .replace(':', "%3A")
        .replace('/', "%2F");
    let form = format!(
        "router=home&url={encoded_url}&login={DEFAULT_LOGIN}&password=&tls=verify&tags=trusted"
    );

    let response = fixture
        .post("/ui/routers/home/edit", &browser, &form)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let stored = fixture.registry().get("home")?.profile;
    assert_eq!(stored.tags, ["trusted"], "metadata is updated");
    assert_eq!(stored.read_login, original.read_login, "read login kept");
    assert_eq!(
        stored.read_password_file, original.read_password_file,
        "read password file kept"
    );
    Ok(())
}
