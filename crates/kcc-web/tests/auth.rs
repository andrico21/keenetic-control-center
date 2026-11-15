//! Web authentication, session, CSRF, authorization, timeout, and bind-policy tests.

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
    clippy::panic_in_result_fn,
    reason = "test assertions deliberately panic and are not rendered API documentation"
)]
mod tests {
    extern crate alloc;

    use alloc::sync::Arc;
    use core::{
        error::Error,
        fmt::{self, Display},
        sync::atomic::{AtomicU64, Ordering},
        time::Duration,
    };

    use axum::{
        Router,
        body::Body,
        http::{Method, Request, StatusCode, header},
        response::Response,
    };
    use kcc_app::{
        accounts::Clock,
        permissions::built_in_roles,
        settings::{Config, ConfigError},
    };
    use kcc_i18n::keys;
    use kcc_web::{session::CookieSecurity, web_router};
    use tower::ServiceExt as _;

    use crate::support::{
        base::{Core, ORIGIN, PASSWORD},
        outcome::TestResult,
        page::{cookie_pair, en, header_text, meta_content, text},
    };

    #[derive(Debug)]
    struct ExpectedValidationError;

    impl Display for ExpectedValidationError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("plain public Web UI validation unexpectedly succeeded")
        }
    }

    impl Error for ExpectedValidationError {}

    const USERNAME: &str = "alice";

    #[derive(Debug, Default)]
    struct MockClock {
        now: AtomicU64,
    }

    impl MockClock {
        fn advance(&self, duration: Duration) {
            let _: u64 = self.now.fetch_add(duration.as_secs(), Ordering::SeqCst);
        }
    }

    impl Clock for MockClock {
        fn unix_seconds(&self) -> u64 {
            self.now.load(Ordering::SeqCst)
        }
    }

    struct Fixture {
        _core: Core,
        router: Router,
        clock: Arc<MockClock>,
    }

    impl Fixture {
        fn new(role: &str, security: CookieSecurity) -> TestResult<Self> {
            let clock = Arc::new(MockClock::default());
            let core = Core::new(Arc::<MockClock>::clone(&clock), &[(USERNAME, role, None)])?;
            let web_state = core.web(
                Vec::from(built_in_roles()),
                (Duration::from_secs(30), Duration::from_secs(300)),
                security,
            );
            Ok(Self {
                _core: core,
                router: web_router(web_state),
                clock,
            })
        }

        async fn send(
            &self,
            request: Request<Body>,
        ) -> Result<Response, Box<dyn Error + Send + Sync>> {
            Ok(self.router.clone().oneshot(request).await?)
        }

        async fn login_page(&self) -> Result<(String, String), Box<dyn Error + Send + Sync>> {
            let response = self
                .send(Request::get("/ui/login").body(Body::empty())?)
                .await?;
            let cookie = cookie_pair(&response)?;
            let html = text(response).await?;
            let csrf = meta_content(&html, "csrf-token").ok_or("missing CSRF meta")?;
            Ok((cookie, csrf))
        }

        async fn login(
            &self,
            cookie: &str,
            csrf: &str,
            password: &str,
        ) -> Result<Response, Box<dyn Error + Send + Sync>> {
            let body = format!(
                "username={USERNAME}&password={}",
                password.replace(' ', "+")
            );
            self.send(
                Request::builder()
                    .method(Method::POST)
                    .uri("/ui/login")
                    .header(header::COOKIE, cookie)
                    .header(header::ORIGIN, ORIGIN)
                    .header("sec-fetch-site", "same-origin")
                    .header("x-csrf-token", csrf)
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(body))?,
            )
            .await
        }

        async fn authenticated(&self) -> Result<(String, String), Box<dyn Error + Send + Sync>> {
            let (anonymous_cookie, login_csrf) = self.login_page().await?;
            let response = self.login(&anonymous_cookie, &login_csrf, PASSWORD).await?;
            let cookie = cookie_pair(&response)?;
            let page = self
                .send(
                    Request::get("/ui/")
                        .header(header::COOKIE, &cookie)
                        .body(Body::empty())?,
                )
                .await?;
            let html = text(page).await?;
            let csrf = meta_content(&html, "csrf-token").ok_or("missing authenticated CSRF")?;
            Ok((cookie, csrf))
        }
    }

    #[tokio::test]
    async fn successful_tls_login_sets_host_cookie_flags_and_rotates_id() -> TestResult {
        let fixture = Fixture::new("admin", CookieSecurity::Tls)?;
        let (anonymous_cookie, csrf) = fixture.login_page().await?;

        let response = fixture.login(&anonymous_cookie, &csrf, PASSWORD).await?;

        assert_eq!(response.status(), StatusCode::SEE_OTHER, "login redirect");
        let set_cookie =
            header_text(&response, header::SET_COOKIE.as_str()).ok_or("missing cookie")?;
        assert!(
            set_cookie.starts_with("__Host-kcc_session="),
            "{set_cookie}"
        );
        for flag in ["; Path=/", "; Secure", "; HttpOnly", "; SameSite=Strict"] {
            assert!(set_cookie.contains(flag), "missing {flag}: {set_cookie}");
        }
        assert_ne!(
            cookie_pair(&response)?,
            anonymous_cookie,
            "id rotates at login"
        );
        Ok(())
    }

    #[tokio::test]
    async fn fifth_wrong_password_locks_the_account_with_uniform_response() -> TestResult {
        let fixture = Fixture::new("admin", CookieSecurity::LoopbackHttp)?;
        let (mut cookie, mut csrf) = fixture.login_page().await?;

        for attempt in 1_u32..=5 {
            let response = fixture.login(&cookie, &csrf, "wrong password").await?;
            assert_eq!(
                response.status(),
                StatusCode::UNAUTHORIZED,
                "attempt {attempt}"
            );
            let html = text(response).await?;
            assert!(
                html.contains(&en(keys::ERRORS_AUTH_FAILED)),
                "attempt {attempt}"
            );
            let page = fixture
                .send(
                    Request::get("/ui/login")
                        .header(header::COOKIE, &cookie)
                        .body(Body::empty())?,
                )
                .await?;
            cookie = cookie_pair(&page)?;
            csrf = meta_content(&text(page).await?, "csrf-token")
                .ok_or("missing CSRF after failure")?;
        }

        let response = fixture.login(&cookie, &csrf, PASSWORD).await?;
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "locked valid login"
        );
        assert!(
            text(response)
                .await?
                .contains(&en(keys::ERRORS_AUTH_FAILED)),
            "lockout stays uniform"
        );
        Ok(())
    }

    #[tokio::test]
    async fn missing_csrf_token_rejects_state_change() -> TestResult {
        let fixture = Fixture::new("admin", CookieSecurity::LoopbackHttp)?;
        let (cookie, _csrf) = fixture.authenticated().await?;

        let response = fixture
            .send(
                Request::post("/ui/logout")
                    .header(header::COOKIE, cookie)
                    .header(header::ORIGIN, ORIGIN)
                    .body(Body::empty())?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::FORBIDDEN, "CSRF-missing");
        Ok(())
    }

    #[tokio::test]
    async fn cross_site_origin_rejects_valid_csrf_token() -> TestResult {
        let fixture = Fixture::new("admin", CookieSecurity::LoopbackHttp)?;
        let (cookie, csrf) = fixture.authenticated().await?;

        let response = fixture
            .send(
                Request::post("/ui/logout")
                    .header(header::COOKIE, cookie)
                    .header(header::ORIGIN, "https://attacker.example")
                    .header("sec-fetch-site", "cross-site")
                    .header("x-csrf-token", csrf)
                    .body(Body::empty())?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::FORBIDDEN, "cross-origin");
        Ok(())
    }

    #[tokio::test]
    async fn viewer_receives_forbidden_page_for_operator_route() -> TestResult {
        let fixture = Fixture::new("viewer", CookieSecurity::LoopbackHttp)?;
        let (cookie, _csrf) = fixture.authenticated().await?;

        let response = fixture
            .send(
                Request::get("/ui/configuration")
                    .header(header::COOKIE, cookie)
                    .body(Body::empty())?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::FORBIDDEN, "permission");
        assert!(
            text(response)
                .await?
                .contains(&en(keys::WEB_ERROR_FORBIDDEN_TITLE)),
            "403 page"
        );
        Ok(())
    }

    #[tokio::test]
    async fn idle_timeout_redirects_to_login_with_mock_clock() -> TestResult {
        let fixture = Fixture::new("admin", CookieSecurity::LoopbackHttp)?;
        let (cookie, _csrf) = fixture.authenticated().await?;
        fixture.clock.advance(Duration::from_secs(31));

        let response = fixture
            .send(
                Request::get("/ui/")
                    .header(header::COOKIE, cookie)
                    .body(Body::empty())?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::SEE_OTHER, "expired session");
        assert_eq!(
            header_text(&response, header::LOCATION.as_str()).as_deref(),
            Some("/ui/login"),
            "login redirect"
        );
        Ok(())
    }

    #[test]
    fn non_loopback_plain_http_web_bind_is_refused() -> TestResult {
        let mut config = Config::default();
        config.server.listen_addr = "0.0.0.0".to_owned();
        config.server.listen_port = 8080;
        config.server.tls_cert_path = None;
        config.server.tls_key_path = None;
        config.web.public_url = None;

        let error = config.validate().err().ok_or(ExpectedValidationError)?;
        assert!(
            matches!(&error, ConfigError::Invalid { field, reason: _ } if field == "server.listen_addr"),
            "{error}"
        );
        Ok(())
    }
}
