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
        audit::{AUDIT_FILE_NAME, receipt::LOGIN_AUDIT_WAIT, verify_chain},
        permissions::built_in_roles,
        persist::StateStore,
        settings::{Config, ConfigError},
    };
    use kcc_i18n::{keys, locale::Locale};
    use kcc_web::{session::CookieSecurity, web_router};
    use tokio::{
        task::JoinSet,
        time::{Instant, timeout},
    };
    use tower::ServiceExt as _;

    use crate::support::{
        base::{Core, ORIGIN, PASSWORD},
        outcome::TestResult,
        page::{cookie_pair, en, header_text, meta_content, said, text},
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
    /// Failed sign-ins sent while the append lock is held: more than the sign-in audit
    /// slots and the old 128-entry queue.
    const FAILED_SIGN_INS: usize = 140;

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
        core: Core,
        router: Router,
        clock: Arc<MockClock>,
    }

    impl Fixture {
        fn new(role: &str, security: CookieSecurity) -> TestResult<Self> {
            let clock = Arc::new(MockClock::default());
            let core = Core::new(
                Arc::<MockClock>::clone(&clock),
                &[(USERNAME, role, None)],
                &[],
            )?;
            let web_state = core.web(
                Vec::from(built_in_roles()),
                (Duration::from_secs(30), Duration::from_secs(300)),
                security,
            );
            Ok(Self {
                core,
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
            self.login_as(cookie, csrf, (USERNAME, password)).await
        }

        async fn login_as(
            &self,
            cookie: &str,
            csrf: &str,
            credentials: (&str, &str),
        ) -> Result<Response, Box<dyn Error + Send + Sync>> {
            self.send(login_request(cookie, csrf, credentials)?).await
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

    /// The sign-in form post of `username` and `password`.
    fn login_request(
        cookie: &str,
        csrf: &str,
        (username, password): (&str, &str),
    ) -> Result<Request<Body>, Box<dyn Error + Send + Sync>> {
        let body = format!(
            "username={username}&password={}",
            password.replace(' ', "+")
        );
        Ok(Request::builder()
            .method(Method::POST)
            .uri("/ui/login")
            .header(header::COOKIE, cookie)
            .header(header::ORIGIN, ORIGIN)
            .header("sec-fetch-site", "same-origin")
            .header("x-csrf-token", csrf)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(body))?)
    }

    /// B-04: a sign-in whose audit entry finds no queue slot in 5 s is refused.
    ///
    /// Another process holds the audit append lock and failed sign-ins took every slot:
    /// the correct sign-in gets no session cookie and no session, and no success entry is
    /// ever written.
    #[tokio::test(start_paused = true)]
    async fn sign_in_is_refused_when_its_audit_entry_cannot_be_queued_in_time() -> TestResult {
        let fixture = Fixture::new("admin", CookieSecurity::LoopbackHttp)?;
        let (cookie, csrf) = fixture.login_page().await?;
        let other_process = StateStore::open(fixture.core.state.dir())?;
        let held = other_process.try_lock(AUDIT_FILE_NAME)?;
        let mut failed = JoinSet::new();
        for _attempt in 0..FAILED_SIGN_INS {
            let request = login_request(&cookie, &csrf, ("nobody", "wrong password"))?;
            drop(failed.spawn(fixture.router.clone().oneshot(request)));
        }
        while let Some(joined) = failed.join_next().await {
            drop(joined??);
        }
        let started = Instant::now();

        let response = timeout(
            Duration::from_secs(120),
            fixture.login(&cookie, &csrf, PASSWORD),
        )
        .await
        .map_err(|_elapsed| "the sign-in hung")??;

        let waited = started.elapsed();
        assert!(
            waited <= LOGIN_AUDIT_WAIT.saturating_add(Duration::from_secs(1)),
            "bounded by the sign-in wait: {waited:?}"
        );
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(
            header_text(&response, header::SET_COOKIE.as_str()).is_none(),
            "no session cookie"
        );
        let home = fixture
            .send(
                Request::get("/ui/")
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(home.status(), StatusCode::SEE_OTHER, "still signed out");
        drop(held);
        assert_eq!(fixture.core.audit.flush(Duration::from_secs(60)).await, 0);
        let entries = verify_chain(fixture.core.state.dir())?;
        assert!(
            !entries
                .iter()
                .any(|entry| entry.action == "web.login" && entry.outcome == "success"),
            "no success entry for a refused sign-in"
        );
        Ok(())
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
                StatusCode::UNPROCESSABLE_ENTITY,
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
            StatusCode::UNPROCESSABLE_ENTITY,
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

    /// SEC1-02: a login with a username of about 1 MiB is refused like an unknown user.
    ///
    /// Its audit entry records the fixed `<invalid-username>` actor instead of the
    /// submitted name, so failed logins cannot grow the audit log unboundedly.
    #[tokio::test]
    async fn oversized_username_is_refused_and_audited_as_a_bounded_marker() -> TestResult {
        let fixture = Fixture::new("admin", CookieSecurity::LoopbackHttp)?;
        let (cookie, csrf) = fixture.login_page().await?;
        let username = "a".repeat(1_000_000);

        let response = fixture
            .login_as(&cookie, &csrf, (&username, "wrong password"))
            .await?;

        assert_eq!(
            response.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "refused"
        );
        let html = text(response).await?;
        assert!(
            html.contains(&en(keys::ERRORS_AUTH_FAILED)),
            "uniform error"
        );
        assert!(!html.contains(&username), "the name is not echoed back");
        let entries = verify_chain(&fixture.core.directory.path().join("state"))?;
        let login = entries
            .iter()
            .find(|entry| entry.action == "web.login")
            .ok_or("missing web.login entry")?;
        assert_eq!(login.outcome, "invalid", "outcome");
        assert_eq!(login.actor.id, "<invalid-username>", "actor marker");
        Ok(())
    }

    /// W1-04, W1-13: a refused sign-in answers 422 in the page's own language.
    ///
    /// The page script swaps a 422 in (it keeps a 401 out), so the browser shows the
    /// uniform error, in the language the sign-in page was shown in.
    #[tokio::test]
    async fn refused_sign_in_answers_422_in_the_page_language() -> TestResult {
        let fixture = Fixture::new("admin", CookieSecurity::LoopbackHttp)?;
        let (cookie, csrf) = fixture.login_page().await?;

        let response = fixture
            .login(&format!("{cookie}; kcc_lang=ru"), &csrf, "wrong password")
            .await?;

        let status = response.status();
        let html = text(response).await?;
        assert!(
            html.contains(&said(Locale::Ru, keys::ERRORS_AUTH_FAILED)),
            "the error in the page's language"
        );
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "refused");
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

    /// W1-18: each rejecting condition refuses a request with a valid CSRF token on its
    /// own: a foreign or missing Origin without Fetch Metadata, and a cross-site fetch
    /// from the right Origin.
    #[tokio::test]
    async fn cross_site_origin_rejects_valid_csrf_token() -> TestResult {
        let fixture = Fixture::new("admin", CookieSecurity::LoopbackHttp)?;
        let (cookie, csrf) = fixture.authenticated().await?;

        for (case, origin, fetch_site) in [
            ("foreign origin", Some("https://attacker.example"), None),
            ("no origin", None, None),
            ("cross-site fetch", Some(ORIGIN), Some("cross-site")),
        ] {
            let mut request = Request::post("/ui/logout")
                .header(header::COOKIE, &cookie)
                .header("x-csrf-token", &csrf);
            if let Some(sent) = origin {
                request = request.header(header::ORIGIN, sent);
            }
            if let Some(sent) = fetch_site {
                request = request.header("sec-fetch-site", sent);
            }
            let response = fixture.send(request.body(Body::empty())?).await?;
            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{case}");
        }
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

    /// SEC1-12: a self-service password change answers with a new session id and CSRF
    /// token; the old id no longer authenticates and the account's other sessions end.
    #[tokio::test]
    async fn own_password_change_rotates_the_session() -> TestResult {
        let fixture = Fixture::new("admin", CookieSecurity::LoopbackHttp)?;
        let (cookie, csrf) = fixture.authenticated().await?;
        let (other, _other_csrf) = fixture.authenticated().await?;
        let replacement = ["rotated", "runtime", "passphrase"].join(" ");
        let body = format!(
            "current_password={}&new_password={}",
            PASSWORD.replace(' ', "+"),
            replacement.replace(' ', "+")
        );

        let changed = fixture
            .send(
                Request::post("/ui/account/password")
                    .header(header::COOKIE, &cookie)
                    .header(header::ORIGIN, ORIGIN)
                    .header("sec-fetch-site", "same-origin")
                    .header("x-csrf-token", &csrf)
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(body))?,
            )
            .await?;

        let rotated = cookie_pair(&changed)?;
        assert_ne!(rotated, cookie, "the session id rotates");
        let landing = header_text(&changed, header::LOCATION.as_str()).ok_or("no redirect")?;
        let page = |held: &str| {
            Request::get(landing.as_str())
                .header(header::COOKIE, held)
                .body(Body::empty())
        };
        let opened = fixture.send(page(&rotated)?).await?;
        assert_eq!(opened.status(), StatusCode::OK, "the new id works");
        let html = text(opened).await?;
        let token = meta_content(&html, "csrf-token").ok_or("missing CSRF")?;
        assert_ne!(token, csrf, "the CSRF token rotates");
        assert!(html.contains(&en(keys::WEB_ACCOUNT_SAVED)), "saved notice");
        for (old, label) in [(&cookie, "the old id"), (&other, "another session")] {
            let refused = fixture.send(page(old)?).await?;
            assert_eq!(
                header_text(&refused, header::LOCATION.as_str()).as_deref(),
                Some("/ui/login"),
                "{label} still authenticates"
            );
        }
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
