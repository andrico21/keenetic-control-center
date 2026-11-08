//! The sign-in page's bare shell, and the signed-in shell that keeps the navigation.

use axum::{
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use kcc_i18n::{bundle::tr, keys, locale::Locale};

use crate::{
    nav_links,
    support::{Fixture, TestResult, header_text, text},
};

/// The browser origin the shared fixture accepts.
const ORIGIN: &str = "http://127.0.0.1:8080";

/// What only a signed-in page has: the navigation and its button, the fleet switcher,
/// and the language menu that saves to the account.
const SIGNED_IN_ONLY: [&str; 4] = [
    "class=\"sidenav\"",
    "popovertarget=\"site-nav\"",
    "class=\"masthead__context\"",
    "data-kcc-locale-action=",
];

/// What the bare shell keeps: the brand and the language and theme menus.
const BARE: [&str; 3] = [
    "class=\"masthead__brand\"",
    "id=\"locale-menu\"",
    "id=\"theme-menu\"",
];

/// Checks that `page`, named `what` in messages, has the bare shell.
fn assert_bare(page: &str, what: &str) {
    for absent in SIGNED_IN_ONLY {
        assert!(!page.contains(absent), "{absent} on {what}: {page}");
    }
    assert!(nav_links(page).is_empty(), "no section links on {what}");
    assert!(
        !page.contains(&tr(Locale::En, keys::WEB_FLEET_EMPTY, None)),
        "no fleet text on {what}"
    );
    for present in BARE {
        assert!(page.contains(present), "{present} on {what}");
    }
}

/// The sign-in page and a refused sign-in show the brand and the two menus only; a
/// signed-in page keeps the navigation, the fleet switcher and the account language menu.
#[tokio::test]
async fn the_sign_in_page_has_a_bare_shell() -> TestResult {
    let fixture = Fixture::new().await?;
    let response = fixture
        .send(Request::get("/ui/login").body(Body::empty())?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK, "sign-in page");
    let cookie = header_text(&response, "set-cookie")
        .and_then(|value| value.split(';').next().map(str::to_owned))
        .ok_or("no session cookie")?;
    let login = text(response).await?;
    assert_bare(&login, "the sign-in page");
    let csrf = login
        .split_once("<meta name=\"csrf-token\" content=\"")
        .and_then(|(_, tail)| tail.split_once('"'))
        .map(|(token, _)| token.to_owned())
        .ok_or("no CSRF token")?;
    let refused = fixture
        .send(
            Request::builder()
                .method(Method::POST)
                .uri("/ui/login")
                .header(header::COOKIE, &cookie)
                .header(header::ORIGIN, ORIGIN)
                .header("sec-fetch-site", "same-origin")
                .header("x-csrf-token", &csrf)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from("username=viewer&password=wrong"))?,
        )
        .await?;
    assert_eq!(refused.status(), StatusCode::UNAUTHORIZED, "refused");
    assert_bare(&text(refused).await?, "the refused sign-in");
    let viewer = fixture.login("viewer").await?;
    let page = text(fixture.get("/ui/account", &viewer).await?).await?;
    for present in SIGNED_IN_ONLY {
        assert!(page.contains(present), "{present} once signed in");
    }
    assert_eq!(nav_links(&page).len(), 14, "every section once signed in");
    Ok(())
}
