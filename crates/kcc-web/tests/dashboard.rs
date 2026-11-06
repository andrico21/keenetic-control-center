//! Fleet overview, router dashboard, router management and live-stream tests against the
//! fake router: per-role controls, the SSE cadence and idle stop under a paused clock,
//! the outbound-policy refusal, write-only passwords and the support-tier notice.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    extern crate alloc;

    use alloc::sync::Arc;
    use core::{
        error::Error,
        net::SocketAddr,
        str,
        sync::atomic::{AtomicU64, Ordering},
        time::Duration,
    };
    use std::fs;

    use axum::{
        Router,
        body::{Body, to_bytes},
        http::{Method, Request, StatusCode, header},
        response::Response,
    };
    use futures_util::StreamExt as _;
    use kcc_app::{
        accounts::{AccountStore, Clock, NewAccount},
        audit::{AuditLog, verify_chain},
        backups::BackupStore,
        permissions::{Role, built_in_roles},
        persist::StateStore,
        poller::Poller,
        registry::{ManagedRouterProfile, RouterRegistry},
        secrets::MasterKey,
        settings::OutboundConfig,
        workflow::ChangeWorkflow,
    };
    use kcc_i18n::{bundle::tr, keys, locale::Locale};
    use kcc_rci::{RciBody, RciPath};
    use kcc_testkit::{
        DEFAULT_LOGIN, DEFAULT_PASSWORD, FakeRouter, Handle,
        model::{Firmware, Model, Profile},
    };
    use kcc_web::{
        WebState, WebStateConfig, fleet::FleetServices, session::CookieSecurity, web_router,
    };
    use secrecy::SecretString;
    use serde_json::Value;
    use tempfile::TempDir;
    use tokio::time::{Instant, sleep, timeout_at};
    use tower::ServiceExt as _;
    use url::Url;

    /// Fallible test result.
    type TestResult = Result<(), Box<dyn Error + Send + Sync>>;

    /// Largest response body a test reads.
    const BODY_CAP: usize = 0x0040_0000;

    /// The only browser origin the fixture accepts.
    const ORIGIN: &str = "http://127.0.0.1:8080";

    /// Password of every fixture account.
    const PASSWORD: &str = "correct horse battery staple";

    /// A second fake-router account whose password appears nowhere else.
    const ROUTER_LOGIN: &str = "kcc";

    /// The password of [`ROUTER_LOGIN`].
    const ROUTER_SECRET: &str = "router-secret-5f2c";

    /// A frozen account and session clock; the tests drive time through tokio.
    #[derive(Debug, Default)]
    struct FrozenClock {
        /// Unix seconds.
        now: AtomicU64,
    }

    impl Clock for FrozenClock {
        fn unix_seconds(&self) -> u64 {
            self.now.load(Ordering::SeqCst)
        }
    }

    /// A signed-in browser: its session cookie and CSRF token.
    struct Browser {
        /// `kcc_session=<id>`.
        cookie: String,
        /// Token for `X-CSRF-Token`.
        csrf: String,
    }

    /// The Web UI over a registry of fake routers, with an account per built-in role and a
    /// Russian-speaking administrator.
    struct Fixture {
        /// State, credentials and router password file.
        directory: TempDir,
        /// The Web UI.
        router: Router,
        /// The registry behind it.
        registry: Arc<RouterRegistry>,
        /// Running fake routers by profile id.
        routers: Vec<(String, Handle)>,
    }

    impl Fixture {
        /// Serves one fake router per `(id, profile)` and registers it.
        async fn new(fakes: &[(&str, Profile)]) -> Result<Self, Box<dyn Error + Send + Sync>> {
            let directory = TempDir::new()?;
            let state = StateStore::open(&directory.path().join("state"))?;
            let clock: Arc<dyn Clock> = Arc::new(FrozenClock::default());
            let accounts = Arc::new(AccountStore::new(
                state.clone(),
                MasterKey::generate()?,
                Duration::from_secs(60),
                Arc::clone(&clock),
            ));
            for role in ["viewer", "operator", "admin"] {
                accounts.create(NewAccount::new(
                    role.to_owned(),
                    SecretString::from(PASSWORD),
                    role.to_owned(),
                ))?;
            }
            accounts.create(
                NewAccount::new(
                    "russian".to_owned(),
                    SecretString::from(PASSWORD),
                    "admin".to_owned(),
                )
                .with_locale("ru".to_owned()),
            )?;
            let password_file = directory.path().join("router-password");
            fs::write(&password_file, DEFAULT_PASSWORD)?;
            let mut outbound = OutboundConfig::default();
            outbound.allow_loopback = true;
            let registry = Arc::new(RouterRegistry::new(state.clone(), &[], &outbound)?);
            let mut routers = Vec::new();
            for (id, profile) in fakes {
                let (address, handle) = FakeRouter::builder(*profile)
                    .user(DEFAULT_LOGIN, DEFAULT_PASSWORD, ["cli", "http-proxy"])
                    .user(ROUTER_LOGIN, ROUTER_SECRET, ["cli", "http-proxy"])
                    .build()?
                    .serve(SocketAddr::from(([127, 0, 0, 1], 0)))
                    .await?;
                registry
                    .create(
                        &admin()?,
                        ManagedRouterProfile::new(
                            (*id).to_owned(),
                            Url::parse(&format!("http://{address}"))?,
                            DEFAULT_LOGIN.to_owned(),
                            password_file.clone(),
                        ),
                    )
                    .await?;
                routers.push(((*id).to_owned(), handle));
            }
            let audit = AuditLog::spawn(&state)?;
            let backups = Arc::new(BackupStore::new(
                state.clone(),
                MasterKey::from_bytes([7_u8; 32]),
            ));
            let workflow =
                ChangeWorkflow::new(state.clone(), Arc::clone(&registry), backups, audit.clone());
            let web = WebState::new(WebStateConfig {
                default_locale: Locale::En,
                accounts,
                audit,
                roles: Vec::from(built_in_roles()),
                session_idle: Duration::from_secs(3_600),
                session_absolute: Duration::from_secs(36_000),
                allowed_origins: vec![ORIGIN.to_owned()],
                cookie_security: CookieSecurity::LoopbackHttp,
                clock,
            })
            .with_fleet(FleetServices {
                registry: Arc::clone(&registry),
                poller: Poller::new(Arc::clone(&registry)),
                workflow,
                credentials_dir: directory.path().join("credentials"),
                update_check: None,
            });
            Ok(Self {
                directory,
                router: web_router(web),
                registry,
                routers,
            })
        }

        /// Sends one request through the Web UI.
        async fn send(
            &self,
            request: Request<Body>,
        ) -> Result<Response, Box<dyn Error + Send + Sync>> {
            Ok(self.router.clone().oneshot(request).await?)
        }

        /// `GET path` as `browser`.
        async fn get(
            &self,
            path: &str,
            browser: &Browser,
        ) -> Result<Response, Box<dyn Error + Send + Sync>> {
            self.send(
                Request::get(path)
                    .header(header::COOKIE, &browser.cookie)
                    .body(Body::empty())?,
            )
            .await
        }

        /// A same-origin form `POST` as `browser`, as htmx sends it.
        async fn post(
            &self,
            path: &str,
            browser: &Browser,
            form: &str,
        ) -> Result<Response, Box<dyn Error + Send + Sync>> {
            self.send(
                Request::builder()
                    .method(Method::POST)
                    .uri(path)
                    .header(header::COOKIE, &browser.cookie)
                    .header(header::ORIGIN, ORIGIN)
                    .header("sec-fetch-site", "same-origin")
                    .header("x-csrf-token", &browser.csrf)
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(form.to_owned()))?,
            )
            .await
        }

        /// Signs `username` in and returns the authenticated browser.
        async fn login(&self, username: &str) -> Result<Browser, Box<dyn Error + Send + Sync>> {
            let page = self
                .send(Request::get("/ui/login").body(Body::empty())?)
                .await?;
            let anonymous = Browser {
                cookie: cookie_pair(&page)?,
                csrf: meta(&text(page).await?).ok_or("login page CSRF")?,
            };
            let password = PASSWORD.replace(' ', "+");
            let response = self
                .post(
                    "/ui/login",
                    &anonymous,
                    &format!("username={username}&password={password}"),
                )
                .await?;
            assert_eq!(response.status(), StatusCode::SEE_OTHER, "{username} login");
            let cookie = cookie_pair(&response)?;
            let account = self
                .send(
                    Request::get("/ui/account")
                        .header(header::COOKIE, &cookie)
                        .body(Body::empty())?,
                )
                .await?;
            let csrf = meta(&text(account).await?).ok_or("account page CSRF")?;
            Ok(Browser { cookie, csrf })
        }

        /// Changes the running configuration of `id` so it has unsaved changes.
        async fn make_unsaved(&self, id: &str) -> TestResult {
            let client = self.registry.client(id).await?;
            drop(
                client
                    .parse("interface Bridge0 description dashboard-test")
                    .await?,
            );
            Ok(())
        }

        /// The handle of fake router `id`.
        fn handle(&self, id: &str) -> Result<&Handle, Box<dyn Error + Send + Sync>> {
            self.routers
                .iter()
                .find_map(|(router, handle)| (router == id).then_some(handle))
                .ok_or_else(|| format!("no fake router {id}").into())
        }
    }

    /// The built-in administrator role.
    fn admin() -> Result<Role, Box<dyn Error + Send + Sync>> {
        built_in_roles()
            .into_iter()
            .find(|role| role.name == "admin")
            .ok_or_else(|| "no admin role".into())
    }

    /// The response body as text.
    async fn text(response: Response) -> Result<String, Box<dyn Error + Send + Sync>> {
        let bytes = to_bytes(response.into_body(), BODY_CAP).await?;
        Ok(String::from_utf8(bytes.to_vec())?)
    }

    /// The `name=value` pair of the response's `Set-Cookie`.
    fn cookie_pair(response: &Response) -> Result<String, Box<dyn Error + Send + Sync>> {
        response
            .headers()
            .get(header::SET_COOKIE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .map(str::to_owned)
            .ok_or_else(|| "missing Set-Cookie".into())
    }

    /// The CSRF token of a rendered page.
    fn meta(html: &str) -> Option<String> {
        html.split_once("<meta name=\"csrf-token\" content=\"")
            .and_then(|(_, tail)| tail.split_once('"'))
            .map(|(token, _)| token.to_owned())
    }

    /// A header of `response` as text.
    fn header_text(response: &Response, name: &str) -> Option<String> {
        response
            .headers()
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
    }

    /// Viewers get no edit controls, operators get Save, administrators get everything,
    /// on the fleet grid, the dashboard and the router forms.
    #[tokio::test]
    async fn each_role_sees_only_the_controls_it_may_use() -> TestResult {
        let fixture = Fixture::new(&[("home", Profile::default())]).await?;
        fixture.make_unsaved("home").await?;
        let banner = tr(Locale::En, keys::WEB_UNSAVED_TEXT, None);
        for (role, can_save, can_manage) in [
            ("viewer", false, false),
            ("operator", true, false),
            ("admin", true, true),
        ] {
            let browser = fixture.login(role).await?;
            let fleet = fixture.get("/ui/", &browser).await?;
            assert_eq!(fleet.status(), StatusCode::OK, "{role}: fleet");
            let grid = text(fleet).await?;
            assert!(grid.contains("id=\"router-home\""), "{role}: card");
            assert!(
                grid.contains(&tr(Locale::En, keys::WEB_ROUTER_ONLINE, None)),
                "{role}: polled card is online"
            );
            assert_eq!(
                grid.contains("href=\"/ui/routers/new\""),
                can_manage,
                "{role}: add router"
            );
            assert_eq!(
                grid.contains("href=\"/ui/routers/home/edit\""),
                can_manage,
                "{role}: edit on the card"
            );
            let dashboard = text(fixture.get("/ui/r/home", &browser).await?).await?;
            assert!(dashboard.contains(&banner), "{role}: unsaved banner");
            assert_eq!(
                dashboard.contains("hx-post=\"/ui/r/home/save\""),
                can_save,
                "{role}: save"
            );
            assert_eq!(
                dashboard.contains("href=\"/ui/routers/home/edit\""),
                can_manage,
                "{role}: edit on the dashboard"
            );
            for form in ["/ui/routers/new", "/ui/routers/home/edit"] {
                let status = fixture.get(form, &browser).await?.status();
                let expected = if can_manage {
                    StatusCode::OK
                } else {
                    StatusCode::FORBIDDEN
                };
                assert_eq!(status, expected, "{role}: {form}");
            }
        }
        Ok(())
    }

    /// The fleet stream carries a card per poll (two within 31 s of the 15 s cadence),
    /// and after the browser disconnects the poller stops within its 2-minute idle window.
    #[tokio::test(start_paused = true)]
    async fn fleet_stream_follows_the_poller_and_releases_it_on_disconnect() -> TestResult {
        let fixture = Fixture::new(&[("home", Profile::default())]).await?;
        let browser = fixture.login("viewer").await?;
        let handle = fixture.handle("home")?;
        let start = Instant::now();
        let deadline = start
            .checked_add(Duration::from_secs(31))
            .ok_or("deadline overflow")?;
        let response = fixture.get("/ui/sse/fleet", &browser).await?;
        assert_eq!(response.status(), StatusCode::OK, "stream opened");
        assert!(
            header_text(&response, "content-type")
                .is_some_and(|value| value.starts_with("text/event-stream")),
            "event stream"
        );
        let mut body = response.into_body().into_data_stream();
        let mut received = String::new();
        let mut counts = Vec::new();
        while received.matches("event: router-home").count() < 2 {
            let chunk = timeout_at(deadline, body.next())
                .await?
                .ok_or("stream ended early")??;
            received.push_str(str::from_utf8(&chunk)?);
            counts.push(handle.request_count());
        }
        assert!(
            start.elapsed() <= Duration::from_secs(31),
            "two polls in 31 s"
        );
        assert!(
            received.contains(&tr(Locale::En, keys::WEB_ROUTER_ONLINE, None)),
            "cards are rendered in the viewer's locale"
        );
        assert!(
            counts.first() < counts.last(),
            "the second card follows a new poll: {counts:?}"
        );
        drop(body);
        sleep(Duration::from_secs(120)).await;
        let settled = handle.request_count();
        sleep(Duration::from_secs(600)).await;
        assert_eq!(
            handle.request_count(),
            settled,
            "no router request more than 2 minutes after the disconnect"
        );
        Ok(())
    }

    /// The dashboard stream opens with the traffic history, then sends the live region.
    #[tokio::test]
    async fn dashboard_stream_opens_with_history_then_the_live_region() -> TestResult {
        let fixture = Fixture::new(&[("home", Profile::default())]).await?;
        let browser = fixture.login("viewer").await?;
        let response = fixture.get("/ui/sse/r/home/traffic", &browser).await?;
        assert_eq!(response.status(), StatusCode::OK, "stream opened");
        let mut body = response.into_body().into_data_stream();
        let mut received = String::new();
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(10))
            .ok_or("deadline overflow")?;
        while !received.contains("event: live") {
            let chunk = timeout_at(deadline, body.next())
                .await?
                .ok_or("stream ended early")??;
            received.push_str(str::from_utf8(&chunk)?);
        }
        let traffic = received.find("event: traffic").ok_or("no traffic event")?;
        let live = received.find("event: live").ok_or("no live event")?;
        assert!(traffic < live, "history first: {received}");
        assert!(
            received.contains("\"replace\":true"),
            "the opening event replaces the chart data"
        );
        assert!(
            received.contains("hx-swap-oob=\"true\""),
            "the live region also refreshes the header status"
        );
        let other = fixture.get("/ui/sse/r/elsewhere/traffic", &browser).await?;
        assert_eq!(other.status(), StatusCode::NOT_FOUND, "unknown router");
        Ok(())
    }

    /// Adding a router at the cloud metadata address is refused with the localized
    /// policy message, by the form and by the connection test, and nothing is stored.
    #[tokio::test]
    async fn metadata_address_is_refused_with_the_localized_policy_message() -> TestResult {
        let fixture = Fixture::new(&[]).await?;
        let browser = fixture.login("russian").await?;
        let secret = "metadata-password-123";
        let form = format!(
            "id=metadata&url=http%3A%2F%2F169.254.169.254&login=admin&password={secret}&tls=verify&tags="
        );
        let refusal = tr(Locale::Ru, keys::WEB_ROUTER_ERROR_POLICY, None);
        let created = fixture.post("/ui/routers/new", &browser, &form).await?;
        assert_eq!(
            created.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "refused form"
        );
        let page = text(created).await?;
        assert!(page.contains(&refusal), "localized refusal: {page}");
        assert!(!page.contains(secret), "the password is never echoed");
        assert!(
            fixture.registry.get("metadata").is_err(),
            "no profile stored"
        );
        let tested = text(fixture.post("/ui/routers/test", &browser, &form).await?).await?;
        assert!(
            tested.contains(&refusal),
            "connection test refusal: {tested}"
        );
        Ok(())
    }

    /// A router added in the Web UI stores its password owner-only, never renders it, and
    /// leaves a credential-free audit event.
    #[tokio::test]
    async fn adding_a_router_stores_the_password_write_only_and_audits() -> TestResult {
        let fixture = Fixture::new(&[("home", Profile::default())]).await?;
        let browser = fixture.login("admin").await?;
        let address = fixture
            .registry
            .get("home")?
            .profile
            .url
            .as_str()
            .trim_end_matches('/')
            .replace(':', "%3A")
            .replace('/', "%2F");
        let form = format!(
            "id=lab&url={address}&login={ROUTER_LOGIN}&password={ROUTER_SECRET}&tls=verify&tags=lab%2C+spare&test_device=on"
        );
        let tested = text(fixture.post("/ui/routers/test", &browser, &form).await?).await?;
        assert!(
            tested.contains(&tr(Locale::En, keys::WEB_TEST_SUCCESS, None)),
            "the test signs in: {tested}"
        );
        let created = fixture.post("/ui/routers/new", &browser, &form).await?;
        assert_eq!(created.status(), StatusCode::OK, "created");
        assert_eq!(
            header_text(&created, "hx-redirect").as_deref(),
            Some("/ui/r/lab"),
            "opens the new dashboard"
        );
        let stored = fixture.registry.get("lab")?.profile;
        assert_eq!(stored.tags, ["lab", "spare"], "tags");
        assert!(stored.test_device, "test-device flag");
        assert_eq!(
            fs::read_to_string(&stored.password_file)?,
            ROUTER_SECRET,
            "password file"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = fs::metadata(&stored.password_file)?.permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "owner-only password file");
        }
        let edit = text(fixture.get("/ui/routers/lab/edit", &browser).await?).await?;
        assert!(
            edit.contains("name=\"password\" type=\"password\" value=\"\""),
            "the password field is rendered empty"
        );
        assert!(
            !edit.contains(ROUTER_SECRET),
            "the password is never rendered"
        );
        let events = verify_chain(&fixture.directory.path().join("state"))?;
        let event = events
            .iter()
            .find(|entry| entry.action == "router.profile_create")
            .ok_or("no create audit event")?;
        assert_eq!(event.router.as_deref(), Some("lab"), "audited router");
        assert!(
            !event.params_redacted.to_string().contains(ROUTER_SECRET),
            "no secret in the audit parameters"
        );
        Ok(())
    }

    /// The 4.3.9 dashboard carries the documentation-based notice and its documentation
    /// link; the hardware-verified 5.1 dashboard does not.
    #[tokio::test]
    async fn only_documentation_based_firmware_shows_the_tier_notice() -> TestResult {
        let legacy = Profile::new(Model::Kn1811, Firmware::V4_3)?;
        let fixture = Fixture::new(&[("legacy", legacy), ("current", Profile::default())]).await?;
        let browser = fixture.login("viewer").await?;
        let badge = tr(Locale::En, keys::WEB_TIER_DOCUMENTATION, None);
        let notice = tr(Locale::En, keys::WEB_TIER_DOCUMENTATION_TEXT, None);
        let old = text(fixture.get("/ui/r/legacy", &browser).await?).await?;
        assert!(old.contains("4.3.9"), "4.3.9 firmware detected");
        assert!(old.contains(&badge), "documentation-based badge");
        assert!(old.contains(&notice), "documentation-based notice");
        assert!(
            old.contains("docs/FIRMWARE.md"),
            "links the firmware document"
        );
        let new = text(fixture.get("/ui/r/current", &browser).await?).await?;
        assert!(new.contains("5.1.3"), "5.1.3 firmware detected");
        assert!(!new.contains(&badge), "no badge on 5.1");
        assert!(!new.contains("docs/FIRMWARE.md"), "no notice on 5.1");
        Ok(())
    }

    /// An operator's Save persists the running configuration through the change
    /// workflow and answers with the localized toast.
    #[tokio::test]
    async fn operator_save_persists_the_running_configuration() -> TestResult {
        let fixture = Fixture::new(&[("home", Profile::default())]).await?;
        fixture.make_unsaved("home").await?;
        let browser = fixture.login("operator").await?;
        let saved = fixture.post("/ui/r/home/save", &browser, "").await?;
        assert_eq!(saved.status(), StatusCode::OK, "save answered");
        let toast = text(saved).await?;
        assert!(
            toast.contains(&tr(Locale::En, keys::WEB_SAVE_DONE, None)),
            "success toast: {toast}"
        );
        let viewer = fixture.login("viewer").await?;
        let denied = fixture.post("/ui/r/home/save", &viewer, "").await?;
        assert_eq!(denied.status(), StatusCode::FORBIDDEN, "viewer cannot save");
        let client = fixture.registry.client("home").await?;
        let last_change = client
            .show(&RciPath::from_segments(["show", "last-change"])?, &())
            .await?;
        assert!(
            matches!(
                &last_change,
                RciBody::Json(response)
                    if response.value.get("unsaved") == Some(&Value::Bool(false))
            ),
            "the router has no unsaved changes: {last_change:?}"
        );
        Ok(())
    }
}
