//! The Web UI over one fake router, with the job runner attached and a signed-in account
//! per built-in role, plus `outsider`, who holds every permission on `lab-*` routers only.
#![expect(
    clippy::missing_errors_doc,
    reason = "test support is not rendered API documentation; every error fails the test"
)]

extern crate alloc;

use alloc::sync::Arc;
use core::{error::Error, net::SocketAddr, time::Duration};
use std::path::PathBuf;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Method, Request, header},
    response::Response,
};
use kcc_app::{
    accounts::{AccountStore, Clock, NewAccount},
    audit::{AuditEntry, AuditLog, verify_chain},
    backups::BackupStore,
    credentials::CredentialStore,
    jobs::JobRunner,
    permissions::{Permission, Role, built_in_roles},
    persist::StateStore,
    poller::Poller,
    registry::{ManagedRouterProfile, RouterRegistry},
    secrets::MasterKey,
    settings::{BackupsConfig, OutboundConfig},
    workflow::ChangeWorkflow,
};
use kcc_i18n::locale::Locale;
use kcc_testkit::{
    DEFAULT_LOGIN, DEFAULT_PASSWORD, FakeRouter, FaultInjection, Handle, model::Profile,
};
use kcc_web::{
    WebState, WebStateConfig,
    fleet::{BackupServices, FleetServices},
    session::CookieSecurity,
    web_router,
};
use secrecy::SecretString;
use tempfile::TempDir;
use tower::ServiceExt as _;
use url::Url;

/// Fallible test result.
pub(crate) type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

/// Largest response body a test reads.
const BODY_CAP: usize = 0x0100_0000;

/// The only browser origin the fixture accepts.
const ORIGIN: &str = "http://127.0.0.1:8080";

/// Password of every fixture account.
const PASSWORD: &str = "correct horse battery staple";

/// The profile id of the fake router.
pub(crate) const ROUTER: &str = "home";

/// A frozen account and session clock; the tests drive time through tokio.
#[derive(Debug, Default)]
struct FrozenClock;

impl Clock for FrozenClock {
    fn unix_seconds(&self) -> u64 {
        1_700_000_000
    }
}

/// A signed-in browser: its session cookie and CSRF token.
pub(crate) struct Browser {
    /// `kcc_session=<id>`.
    cookie: String,
    /// Token for `X-CSRF-Token`.
    csrf: String,
}

/// The Web UI over one fake router.
pub(crate) struct Fixture {
    /// State and credentials.
    directory: TempDir,
    /// The Web UI.
    router: Router,
    /// The registry behind it.
    registry: Arc<RouterRegistry>,
    /// The fake router.
    handle: Handle,
}

impl Fixture {
    /// The fixture over a default fake router.
    pub(crate) async fn new() -> TestResult<Self> {
        Self::with_faults(FaultInjection::default()).await
    }

    /// The fixture over a fake router with `faults`.
    pub(crate) async fn with_faults(faults: FaultInjection) -> TestResult<Self> {
        Self::with_router(
            FakeRouter::builder(Profile::default())
                .faults(faults)
                .build()?,
        )
        .await
    }

    /// The fixture over a caller-configured router mode and faults.
    // NOT cancel-safe: setup creates router and application tasks.
    pub(crate) async fn with_router(fake: FakeRouter) -> TestResult<Self> {
        let directory = TempDir::new()?;
        let state = StateStore::open(&directory.path().join("state"))?;
        let clock: Arc<dyn Clock> = Arc::new(FrozenClock);
        let accounts = Arc::new(AccountStore::new(
            state.clone(),
            MasterKey::generate()?,
            Duration::from_secs(60),
            Arc::clone(&clock),
        ));
        for role in [
            "viewer",
            "operator",
            "admin",
            "outsider",
            "raw-writer",
            "rawdes",
            "writer",
        ] {
            accounts.create(NewAccount::new(
                role.to_owned(),
                SecretString::from(PASSWORD),
                role.to_owned(),
            ))?;
        }
        accounts.create(
            NewAccount::new(
                "ukrainian".to_owned(),
                SecretString::from(PASSWORD),
                "admin".to_owned(),
            )
            .with_locale("uk".to_owned()),
        )?;
        let password_file =
            kcc_testkit::write_secret_file(directory.path(), "router-password", DEFAULT_PASSWORD)?;
        let mut outbound = OutboundConfig::default();
        outbound.allow_loopback = true;
        let registry = Arc::new(RouterRegistry::new(state.clone(), &[], &outbound)?);
        let (address, handle) = fake.serve(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        registry
            .create(
                &admin()?,
                ManagedRouterProfile::new(
                    ROUTER.to_owned(),
                    Url::parse(&format!("http://{address}"))?,
                    DEFAULT_LOGIN.to_owned(),
                    password_file,
                ),
            )
            .await?;
        let audit = AuditLog::spawn(&state)?;
        let backups = Arc::new(BackupStore::new(
            state.clone(),
            MasterKey::from_bytes([7_u8; 32]),
        ));
        let workflow = ChangeWorkflow::new(
            state.clone(),
            Arc::clone(&registry),
            Arc::clone(&backups),
            audit.clone(),
        );
        let jobs = JobRunner::open(state.clone(), Arc::clone(&registry), audit.clone()).await?;
        let web = WebState::new(WebStateConfig {
            default_locale: Locale::En,
            accounts,
            audit,
            roles: roles(),
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
            credentials: Arc::new(CredentialStore::new(state.clone(), MasterKey::generate()?)),
            update_check: None,
            backups: Some(BackupServices::new(backups, BackupsConfig::default())),
        })
        .with_jobs(jobs);
        Ok(Self {
            directory,
            router: web_router(web),
            registry,
            handle,
        })
    }

    /// Sends one request through the Web UI.
    pub(crate) async fn send(&self, request: Request<Body>) -> TestResult<Response> {
        Ok(self.router.clone().oneshot(request).await?)
    }

    /// `GET path` as `browser`.
    pub(crate) async fn get(&self, path: &str, browser: &Browser) -> TestResult<Response> {
        self.send(
            Request::get(path)
                .header(header::COOKIE, &browser.cookie)
                .body(Body::empty())?,
        )
        .await
    }

    /// A same-origin form `POST` as `browser`, as htmx sends it.
    pub(crate) async fn post(
        &self,
        path: &str,
        browser: &Browser,
        form: &str,
    ) -> TestResult<Response> {
        self.send(
            Request::builder()
                .method(Method::POST)
                .uri(path)
                .header(header::COOKIE, &browser.cookie)
                .header(header::ORIGIN, ORIGIN)
                .header("sec-fetch-site", "same-origin")
                .header("hx-request", "true")
                .header("x-csrf-token", &browser.csrf)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form.to_owned()))?,
        )
        .await
    }

    /// Signs `username` in and returns the authenticated browser.
    pub(crate) async fn login(&self, username: &str) -> TestResult<Browser> {
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

    /// The fake router.
    pub(crate) const fn handle(&self) -> &Handle {
        &self.handle
    }

    /// The registry, for direct router access in test setup.
    pub(crate) fn registry(&self) -> &RouterRegistry {
        &self.registry
    }

    /// The audit log so far, verified.
    pub(crate) fn audit(&self) -> TestResult<Vec<AuditEntry>> {
        Ok(verify_chain(&self.state_dir())?)
    }

    /// The router's backups.
    pub(crate) fn backups(&self) -> TestResult<usize> {
        let store = BackupStore::new(
            StateStore::open(&self.state_dir())?,
            MasterKey::from_bytes([7_u8; 32]),
        );
        Ok(store.list(ROUTER)?.len())
    }

    /// The state directory.
    pub(crate) fn state_dir(&self) -> PathBuf {
        self.directory.path().join("state")
    }
}

/// Built-in and scoped custom roles used by the browser fixture.
fn roles() -> Vec<Role> {
    built_in_roles()
        .into_iter()
        .chain([
            Role::new(
                "writer".to_owned(),
                [Permission::Read, Permission::Write],
                vec!["*".to_owned()],
            ),
            Role::new(
                "rawdes".to_owned(),
                [
                    Permission::Read,
                    Permission::RawRci,
                    Permission::Destructive,
                ],
                vec!["*".to_owned()],
            ),
            Role::new(
                "outsider".to_owned(),
                Permission::ALL,
                vec!["lab-*".to_owned()],
            ),
            Role::new(
                "raw-writer".to_owned(),
                [Permission::Read, Permission::Write, Permission::RawRci],
                vec!["*".to_owned()],
            ),
        ])
        .collect()
}

/// The built-in administrator role.
fn admin() -> TestResult<Role> {
    built_in_roles()
        .into_iter()
        .find(|role| role.name == "admin")
        .ok_or_else(|| "no admin role".into())
}

/// The response body as text.
pub(crate) async fn text(response: Response) -> TestResult<String> {
    let bytes = to_bytes(response.into_body(), BODY_CAP).await?;
    Ok(String::from_utf8(bytes.to_vec())?)
}

/// A header of `response` as text.
pub(crate) fn header_text(response: &Response, name: &str) -> Option<String> {
    response
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

/// The `name=value` pair of the response's `Set-Cookie`.
fn cookie_pair(response: &Response) -> TestResult<String> {
    header_text(response, "set-cookie")
        .and_then(|value| value.split(';').next().map(str::to_owned))
        .ok_or_else(|| "missing Set-Cookie".into())
}

/// The CSRF token of a rendered page.
fn meta(html: &str) -> Option<String> {
    html.split_once("<meta name=\"csrf-token\" content=\"")
        .and_then(|(_, tail)| tail.split_once('"'))
        .map(|(token, _)| token.to_owned())
}
