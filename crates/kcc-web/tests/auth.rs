//! Web authentication, session, CSRF, authorization, timeout, and bind-policy tests.

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
        body::{Body, to_bytes},
        http::{Method, Request, StatusCode, header},
        response::Response,
    };
    use kcc_app::{
        accounts::{AccountStore, Clock, NewAccount},
        audit::AuditLog,
        permissions::built_in_roles,
        persist::StateStore,
        secrets::MasterKey,
        settings::Config,
    };
    use kcc_i18n::locale::Locale;
    use kcc_web::{WebState, WebStateConfig, session::CookieSecurity, web_router};
    use secrecy::SecretString;
    use tempfile::TempDir;
    use tower::ServiceExt as _;

    #[derive(Debug)]
    struct ExpectedValidationError;

    impl Display for ExpectedValidationError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("plain public Web UI validation unexpectedly succeeded")
        }
    }

    impl Error for ExpectedValidationError {}

    type TestResult = Result<(), Box<dyn Error>>;
    const BODY_CAP: usize = 0x0010_0000;
    const USERNAME: &str = "alice";
    const PASSWORD: &str = "correct horse battery staple";
    const ORIGIN: &str = "http://127.0.0.1:8080";

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
        _directory: TempDir,
        router: Router,
        clock: Arc<MockClock>,
    }

    impl Fixture {
        fn new(role: &str, security: CookieSecurity) -> Result<Self, Box<dyn Error>> {
            let directory = TempDir::new()?;
            let state = StateStore::open(&directory.path().join("state"))?;
            let clock = Arc::new(MockClock::default());
            let account_clock: Arc<dyn Clock> = Arc::<MockClock>::clone(&clock);
            let accounts = Arc::new(AccountStore::new(
                state.clone(),
                MasterKey::generate()?,
                Duration::from_secs(60),
                account_clock,
            ));
            accounts.create(NewAccount::new(
                USERNAME.to_owned(),
                SecretString::from(PASSWORD),
                role.to_owned(),
            ))?;
            let audit = AuditLog::spawn(&state)?;
            let session_clock: Arc<dyn Clock> = Arc::<MockClock>::clone(&clock);
            let web_state = WebState::new(WebStateConfig {
                default_locale: Locale::En,
                accounts,
                audit,
                roles: Vec::from(built_in_roles()),
                session_idle: Duration::from_secs(30),
                session_absolute: Duration::from_secs(300),
                allowed_origins: vec![ORIGIN.to_owned()],
                cookie_security: security,
                clock: session_clock,
            });
            Ok(Self {
                _directory: directory,
                router: web_router(web_state),
                clock,
            })
        }

        async fn send(&self, request: Request<Body>) -> Result<Response, Box<dyn Error>> {
            Ok(self.router.clone().oneshot(request).await?)
        }

        async fn login_page(&self) -> Result<(String, String), Box<dyn Error>> {
            let response = self
                .send(Request::get("/ui/login").body(Body::empty())?)
                .await?;
            let cookie = cookie_pair(&response)?;
            let html = response_text(response).await?;
            let csrf = meta_content(&html, "csrf-token").ok_or("missing CSRF meta")?;
            Ok((cookie, csrf))
        }

        async fn login(
            &self,
            cookie: &str,
            csrf: &str,
            password: &str,
        ) -> Result<Response, Box<dyn Error>> {
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

        async fn authenticated(&self) -> Result<(String, String), Box<dyn Error>> {
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
            let html = response_text(page).await?;
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
        let set_cookie = header_text(&response, header::SET_COOKIE).ok_or("missing cookie")?;
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
            let html = response_text(response).await?;
            assert!(
                html.contains("Invalid username or password."),
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
            csrf = meta_content(&response_text(page).await?, "csrf-token")
                .ok_or("missing CSRF after failure")?;
        }

        let response = fixture.login(&cookie, &csrf, PASSWORD).await?;
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "locked valid login"
        );
        assert!(
            response_text(response)
                .await?
                .contains("Invalid username or password."),
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
            response_text(response).await?.contains("Access denied"),
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
            header_text(&response, header::LOCATION).as_deref(),
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
            error
                .to_string()
                .contains("non-loopback Web UI requires TLS"),
            "{error}"
        );
        Ok(())
    }

    async fn response_text(response: Response) -> Result<String, Box<dyn Error>> {
        let bytes = to_bytes(response.into_body(), BODY_CAP).await?;
        Ok(String::from_utf8(bytes.to_vec())?)
    }

    fn header_text(response: &Response, name: header::HeaderName) -> Option<String> {
        response
            .headers()
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
    }

    fn cookie_pair(response: &Response) -> Result<String, Box<dyn Error>> {
        header_text(response, header::SET_COOKIE)
            .and_then(|value| value.split(';').next().map(str::to_owned))
            .ok_or_else(|| "missing Set-Cookie".into())
    }

    fn meta_content(html: &str, name: &str) -> Option<String> {
        let marker = format!("<meta name=\"{name}\" content=\"");
        html.split_once(&marker)
            .and_then(|(_, tail)| tail.split_once('\"'))
            .map(|(value, _)| value.to_owned())
    }
}
