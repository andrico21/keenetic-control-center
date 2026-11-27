//! The connection test of the router form signs in the way the form says and never shows
//! a server path.

use core::{net::SocketAddr, sync::atomic::Ordering};

use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_testkit::{
    DEFAULT_LOGIN, DEFAULT_PASSWORD, FakeRouter, FaultInjection,
    auth_fixture::{self, Options, Protocol},
    model::Profile,
};

use crate::{
    support::{
        outcome::TestResult,
        page::{en, en_with, form, html, text},
    },
    tests::fleet,
};

/// The dummy token the token fixture accepts.
fn fixture_token() -> String {
    ["fixture", "token"].join("-")
}

/// W1-06: in sign-in mode `token` the typed token is what the add form test signs in with.
///
/// With or without an id the router sees the token header and no password sign-in, and
/// the page is not the id or password refusal.
#[tokio::test]
async fn a_typed_token_is_what_the_add_form_test_signs_in_with() -> TestResult {
    let fixture = fleet(&[]).await?;
    let browser = fixture.login("admin").await?;
    let mut options = Options::default();
    options.protocol = Protocol::Token;
    let (address, handle, counts) = auth_fixture::spawn(options).await?;
    let url = format!("http://{address}");
    let refusals = [
        tr(Locale::En, keys::WEB_ROUTER_ERROR_ID, None),
        tr(Locale::En, keys::WEB_ROUTER_ERROR_PASSWORD, None),
    ];
    for (round, id) in ["lab", ""].into_iter().enumerate() {
        let before = counts.token_requests.load(Ordering::SeqCst);
        let body = form(&[
            ("id", id),
            ("url", &url),
            ("login", DEFAULT_LOGIN),
            ("auth", "token"),
            ("token", &fixture_token()),
            ("tls", "verify"),
        ]);

        let page = text(fixture.post("/ui/routers/test", &browser, &body).await?).await?;

        assert!(
            counts.token_requests.load(Ordering::SeqCst) > before,
            "token requests in round {round}"
        );
        assert_eq!(
            counts.ndw2_posts.load(Ordering::SeqCst) + counts.phase_two.load(Ordering::SeqCst),
            0,
            "no password sign-in"
        );
        for refusal in &refusals {
            assert!(!page.contains(refusal), "round {round}: {page}");
        }
    }
    assert!(
        fixture.registry().get("lab").is_err(),
        "a tested connection stores nothing"
    );
    handle.shutdown().await?;
    Ok(())
}

/// W1-06: the selected sign-in mode reaches the router.
///
/// Mode `digest` signs each request with digest authentication, which the default mode
/// does not.
#[tokio::test]
async fn the_test_uses_the_selected_password_sign_in_mode() -> TestResult {
    let fixture = fleet(&[]).await?;
    let browser = fixture.login("admin").await?;
    let mut options = Options::default();
    options.protocol = Protocol::DigestSha256;
    let (address, handle, counts) = auth_fixture::spawn(options).await?;
    let body = form(&[
        ("id", "lab"),
        ("url", &format!("http://{address}")),
        ("login", DEFAULT_LOGIN),
        ("auth", "digest"),
        ("password", DEFAULT_PASSWORD),
        ("tls", "verify"),
    ]);

    drop(text(fixture.post("/ui/routers/test", &browser, &body).await?).await?);

    assert!(
        counts.digest_requests.load(Ordering::SeqCst) > 0,
        "digest-authenticated requests"
    );
    handle.shutdown().await?;
    Ok(())
}

/// The connection test page for a fake router with `faults`, signed in with typed
/// credentials.
async fn test_page_with(faults: FaultInjection) -> TestResult<String> {
    let fixture = fleet(&[]).await?;
    let browser = fixture.login("admin").await?;
    let (address, handle) = FakeRouter::builder(Profile::default())
        .user(DEFAULT_LOGIN, DEFAULT_PASSWORD, ["cli", "http-proxy"])
        .faults(faults)
        .build()?
        .serve(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await?;
    let body = form(&[
        ("id", "lab"),
        ("url", &format!("http://{address}")),
        ("login", DEFAULT_LOGIN),
        ("password", DEFAULT_PASSWORD),
        ("tls", "verify"),
    ]);
    let page = text(fixture.post("/ui/routers/test", &browser, &body).await?).await?;
    handle.shutdown().await?;
    Ok(page)
}

/// Todo 8: a router that closed the connection did not answer, and the test shows how
/// under the "Details" label.
#[tokio::test]
async fn a_closed_connection_shows_its_cause_under_details() -> TestResult {
    let page =
        test_page_with(FaultInjection::default().close_before_answer("show/version")).await?;
    assert!(
        page.contains(&en(keys::WEB_ROUTER_ERROR_UNREACHABLE)),
        "{page}"
    );
    assert!(page.contains(&en(keys::WEB_KIT_DETAILS)), "{page}");
    assert!(
        page.contains(&html("the router closed the connection before answering")),
        "{page}"
    );
    Ok(())
}

/// Todo 8: an HTTP error status is told with its status, not as a failed check.
#[tokio::test]
async fn an_http_error_names_its_status() -> TestResult {
    let page =
        test_page_with(FaultInjection::default().fail_read_matching("show/version", 1)).await?;
    assert!(
        page.contains(&en_with(keys::WEB_KIT_HTTP_ERROR, &[("status", "500")])),
        "{page}"
    );
    assert!(!page.contains(&en(keys::WEB_ROUTER_ERROR_CHECK)), "{page}");
    Ok(())
}

/// W1-15: a credential file that others can read gets the chmod hint without its path.
///
/// The page the Web user sees does not name the file.
#[cfg(unix)]
#[tokio::test]
async fn a_readable_credential_file_is_refused_without_its_path() -> TestResult {
    use std::{fs, os::unix::fs::PermissionsExt as _};

    use kcc_app::registry::ManagedRouterProfile;

    use crate::{
        router_credentials::{dummy, origin},
        support::build::admin,
    };

    let fixture = fleet(&[("home", Profile::default())]).await?;
    let browser = fixture.login("admin").await?;
    let secret = fixture
        .directory()
        .join(format!("{}.pw", dummy("operator")?));
    fs::write(&secret, DEFAULT_PASSWORD)?;
    fs::set_permissions(&secret, fs::Permissions::from_mode(0o644))?;
    let url = origin(&fixture, "home")?;
    let profile = ManagedRouterProfile::new(
        "operator".to_owned(),
        url.parse()?,
        DEFAULT_LOGIN.to_owned(),
        secret.clone(),
    );
    fixture.registry().create(&admin()?, profile).await?;
    let body = form(&[
        ("router", "operator"),
        ("url", &url),
        ("login", DEFAULT_LOGIN),
        ("tls", "verify"),
    ]);

    let page = text(fixture.post("/ui/routers/test", &browser, &body).await?).await?;

    let hint = tr(Locale::En, keys::WEB_ROUTER_ERROR_PERMISSIONS, None);
    assert!(page.contains(&hint), "chmod hint: {page}");
    assert!(
        !page.contains(&secret.display().to_string()),
        "the server path stays off the page: {page}"
    );
    Ok(())
}
