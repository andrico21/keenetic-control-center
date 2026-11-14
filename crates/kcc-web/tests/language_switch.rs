//! Switching the language while signed in.
//!
//! The masthead language menu and the account page both change the account's language and
//! the live session's, so the next page renders in it without signing in again. Nobody
//! changes another account's language, an unknown language changes nothing, and a page
//! for a visitor who is not signed in keeps following the `kcc_lang` cookie.

#[expect(
    dead_code,
    reason = "the shared Web UI test support; this suite needs part of it"
)]
#[path = "support/mod.rs"]
mod support;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use axum::{
        body::Body,
        http::{Method, Request, StatusCode, header},
    };
    use kcc_i18n::{keys, locale::Locale};

    use crate::support::{
        outcome::TestResult,
        page::{header_text, said, text},
        web::{Browser, Fixture},
    };

    /// The password of every account of the shared fixture.
    const PASSWORD: &str = "correct horse battery staple";

    /// Where the language menu and the account page save the account's language.
    const LOCALE: &str = "/ui/account/locale";

    /// A page every signed-in account may open; it does not ask the router.
    const PAGE: &str = "/ui/clients";

    /// The marker that makes the language menu save to the account.
    const MENU_SAVES: &str = "data-kcc-locale-action=\"/ui/account/locale\"";

    /// The `lang` attribute of a rendered page.
    fn lang(html: &str) -> Option<&str> {
        html.split_once("<html lang=\"")
            .and_then(|(_, tail)| tail.split_once('"'))
            .map(|(tag, _)| tag)
    }

    /// [`PAGE`] as `browser` sees it now.
    async fn next_page(fixture: &Fixture, browser: &Browser) -> TestResult<String> {
        let response = fixture.get(PAGE, browser).await?;
        assert_eq!(response.status(), StatusCode::OK, "{PAGE}");
        text(response).await
    }

    /// The masthead menu posts the chosen language to the account; the next page is in it.
    #[tokio::test]
    async fn the_menu_choice_renders_the_next_page_in_that_language() -> TestResult {
        let fixture = Fixture::new().await?;
        let operator = fixture.login("operator").await?;
        let before = next_page(&fixture, &operator).await?;
        assert_eq!(lang(&before), Some("en"), "the account's language");
        let chosen = fixture.post(LOCALE, &operator, "locale=de").await?;
        assert_eq!(chosen.status(), StatusCode::OK, "saved");
        let after = next_page(&fixture, &operator).await?;
        assert_eq!(lang(&after), Some("de"), "the next page is German");
        assert!(
            after.contains(&said(Locale::De, keys::WEB_THEME_DARK)),
            "its strings too: {after}"
        );
        assert!(
            before.contains(MENU_SAVES) && after.contains(MENU_SAVES),
            "the signed-in menu saves to the account"
        );
        Ok(())
    }

    /// Saving a language on the account page answers in it and keeps it for the next page.
    #[tokio::test]
    async fn the_account_page_language_applies_to_the_next_page() -> TestResult {
        let fixture = Fixture::new().await?;
        let admin = fixture.login("admin").await?;
        let account = text(fixture.get("/ui/account", &admin).await?).await?;
        assert!(
            account.contains("hx-post=\"/ui/account/locale\""),
            "the account form posts to the same place"
        );
        let saved = fixture.post(LOCALE, &admin, "locale=kk").await?;
        assert_eq!(saved.status(), StatusCode::OK, "saved");
        let answer = text(saved).await?;
        assert_eq!(lang(&answer), Some("kk"), "the answer");
        assert!(
            answer.contains(&said(Locale::Kk, keys::WEB_ACCOUNT_SAVED)),
            "the saved notice: {answer}"
        );
        let after = next_page(&fixture, &admin).await?;
        assert_eq!(lang(&after), Some("kk"), "the next page is Kazakh");
        assert!(
            after.contains(&said(Locale::Kk, keys::WEB_CLIENTS_TITLE)),
            "its strings too: {after}"
        );
        Ok(())
    }

    /// The form names no account, and a change touches only the caller's own sessions.
    #[tokio::test]
    async fn nobody_changes_another_accounts_language() -> TestResult {
        let fixture = Fixture::new().await?;
        let viewer = fixture.login("viewer").await?;
        let operator = fixture.login("operator").await?;
        let smuggled = fixture
            .post(LOCALE, &operator, "locale=de&username=viewer")
            .await?;
        assert!(
            smuggled.status().is_client_error(),
            "no account field: {}",
            smuggled.status()
        );
        let own = fixture.post(LOCALE, &operator, "locale=de").await?;
        assert_eq!(own.status(), StatusCode::OK, "own language saved");
        assert_eq!(
            lang(&next_page(&fixture, &operator).await?),
            Some("de"),
            "the caller's session"
        );
        assert_eq!(
            lang(&next_page(&fixture, &viewer).await?),
            Some("en"),
            "the viewer's live session"
        );
        let viewer_again = fixture.login("viewer").await?;
        assert_eq!(
            lang(&next_page(&fixture, &viewer_again).await?),
            Some("en"),
            "the viewer's account"
        );
        Ok(())
    }

    /// A language kcc does not have is refused and the account keeps its own.
    #[tokio::test]
    async fn an_unknown_language_is_refused_and_changes_nothing() -> TestResult {
        let fixture = Fixture::new().await?;
        let operator = fixture.login("operator").await?;
        for body in ["locale=xx", "locale=", "locale=%3Cscript%3E"] {
            let refused = fixture.post(LOCALE, &operator, body).await?;
            assert_eq!(
                refused.status(),
                StatusCode::UNPROCESSABLE_ENTITY,
                "{body} is refused"
            );
        }
        assert_eq!(
            lang(&next_page(&fixture, &operator).await?),
            Some("en"),
            "the session keeps its language"
        );
        let again = fixture.login("operator").await?;
        assert_eq!(
            lang(&next_page(&fixture, &again).await?),
            Some("en"),
            "so does the account"
        );
        Ok(())
    }

    /// The sign-in page follows the `kcc_lang` cookie, and its menu writes only the cookie.
    #[tokio::test]
    async fn signed_out_pages_follow_the_cookie() -> TestResult {
        let fixture = Fixture::new().await?;
        let response = fixture
            .send(
                Request::get("/ui/login")
                    .header(header::COOKIE, "kcc_lang=uk")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK, "sign-in page");
        let page = text(response).await?;
        assert_eq!(lang(&page), Some("uk"), "the cookie's language");
        assert!(
            page.contains("data-kcc-locale=\"uk\" aria-current=\"true\""),
            "the menu marks it"
        );
        assert!(!page.contains(MENU_SAVES), "no account to save to");
        Ok(())
    }

    /// Signing in or out through htmx loads the next page whole, so the language menu and
    /// every form there send that page's CSRF token, not the previous session's.
    #[tokio::test]
    async fn signing_in_and_out_load_the_next_page_whole() -> TestResult {
        let fixture = Fixture::new().await?;
        let page = fixture
            .send(Request::get("/ui/login").body(Body::empty())?)
            .await?;
        let anonymous = header_text(&page, "set-cookie")
            .and_then(|value| value.split(';').next().map(str::to_owned))
            .ok_or("no session cookie")?;
        let html = text(page).await?;
        let csrf = html
            .split_once("<meta name=\"csrf-token\" content=\"")
            .and_then(|(_, tail)| tail.split_once('"'))
            .map(|(token, _)| token.to_owned())
            .ok_or("no CSRF token")?;
        let password = PASSWORD.replace(' ', "+");
        let signed_in = fixture
            .send(
                Request::builder()
                    .method(Method::POST)
                    .uri("/ui/login")
                    .header(header::COOKIE, &anonymous)
                    .header(header::ORIGIN, "http://127.0.0.1:8080")
                    .header("sec-fetch-site", "same-origin")
                    .header("hx-request", "true")
                    .header("x-csrf-token", &csrf)
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(format!("username=operator&password={password}")))?,
            )
            .await?;
        assert_eq!(
            header_text(&signed_in, "hx-redirect").as_deref(),
            Some("/ui/"),
            "a whole page after signing in"
        );
        assert!(
            header_text(&signed_in, "set-cookie").is_some(),
            "with the new session"
        );
        let operator = fixture.login("operator").await?;
        let signed_out = fixture.post("/ui/logout", &operator, "").await?;
        assert_eq!(
            header_text(&signed_out, "hx-redirect").as_deref(),
            Some("/ui/login"),
            "a whole sign-in page after signing out"
        );
        Ok(())
    }
}
