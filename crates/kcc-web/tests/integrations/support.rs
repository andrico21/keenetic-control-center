//! The Web UI over one fake router `home`, with the pieces `kcc serve` wires around it.
//!
//! A hand-moved clock, an optional firmware-update check that reports each finished
//! check, and optional router log collectors.
#![expect(
    clippy::missing_errors_doc,
    reason = "test support returns the boxed error of whatever setup step failed"
)]

extern crate alloc;

use alloc::sync::Arc;
use core::{error::Error, net::SocketAddr, sync::atomic::AtomicU64, time::Duration};
use std::fs;

use axum::{
    Router,
    body::Body,
    http::{Method, Request, header},
    response::Response,
};
use kcc_app::{
    accounts::{AccountStore, NewAccount},
    audit::AuditLog,
    backups::BackupStore,
    credentials::CredentialStore,
    permissions::{Role, built_in_roles},
    persist::StateStore,
    poller::Poller,
    registry::{ManagedRouterProfile, RouterRegistry},
    secrets::MasterKey,
    settings::OutboundConfig,
    workflow::ChangeWorkflow,
};
use kcc_i18n::locale::Locale;
use kcc_telemetry::logs::runtime::Service as LogService;
use kcc_testkit::{DEFAULT_LOGIN, DEFAULT_PASSWORD, FakeRouter, Handle, model::Profile};
use kcc_web::{
    WebState, WebStateConfig,
    fleet::{FleetServices, UpdateCheck, UpdateStatus},
    fleet_updates::ComponentsUpdateCheck,
    session::CookieSecurity,
    web_router,
};
use secrecy::SecretString;
use tempfile::TempDir;
use tokio::{sync::mpsc, time::timeout};
use tower::ServiceExt as _;
use url::Url;

use crate::wiring::{HandClock, Options, Reporting, collector, cookie_pair, text};

/// Fallible test result.
pub(crate) type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

/// The profile id of the fake router.
pub(crate) const ROUTER: &str = "home";

/// The only browser origin the fixture accepts.
const ORIGIN: &str = "http://127.0.0.1:8080";

/// Password of every fixture account.
const PASSWORD: &str = "correct horse battery staple";

/// A signed-in browser: its session cookie.
pub(crate) struct Browser {
    /// `kcc_session=<id>`.
    cookie: String,
}

/// The Web UI over one fake router.
pub(crate) struct Fixture {
    /// State and credentials.
    _directory: TempDir,
    /// The Web UI.
    router: Router,
    /// The state behind it.
    web: WebState,
    /// The registry behind it.
    registry: Arc<RouterRegistry>,
    /// The shared poller.
    poller: Arc<Poller>,
    /// The fixture clock.
    clock: Arc<HandClock>,
    /// The fake router.
    handle: Handle,
    /// Finished update checks.
    checks: mpsc::UnboundedReceiver<UpdateStatus>,
    /// The log collectors, when started.
    logs: Option<LogService>,
}

impl Fixture {
    /// The fixture with `options`.
    pub(crate) async fn new(options: Options) -> TestResult<Self> {
        let directory = TempDir::new()?;
        let state = StateStore::open(&directory.path().join("state"))?;
        let clock = Arc::new(HandClock::new(AtomicU64::new(1_700_000_000)));
        let accounts = Arc::new(AccountStore::new(
            state.clone(),
            MasterKey::generate()?,
            Duration::from_secs(60),
            Arc::<HandClock>::clone(&clock),
        ));
        accounts.create(NewAccount::new(
            "viewer".to_owned(),
            SecretString::from(PASSWORD),
            "viewer".to_owned(),
        ))?;
        let password_file = directory.path().join("router-password");
        fs::write(&password_file, DEFAULT_PASSWORD)?;
        let mut outbound = OutboundConfig::default();
        outbound.allow_loopback = true;
        let registry = Arc::new(RouterRegistry::new(state.clone(), &[], &outbound)?);
        let mut fake = FakeRouter::builder(Profile::default())
            .faults(options.faults())
            .build()?;
        if let Some(update) = options.firmware() {
            fake = fake.with_firmware_update(update);
        }
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
        let workflow =
            ChangeWorkflow::new(state.clone(), Arc::clone(&registry), backups, audit.clone());
        let poller = Poller::new(Arc::clone(&registry));
        let (done, checks) = mpsc::unbounded_channel();
        let update_check: Option<Arc<dyn UpdateCheck>> = options.firmware().map(|_| {
            let check: Arc<dyn UpdateCheck> = Arc::new(Reporting::new(
                ComponentsUpdateCheck::new(
                    Arc::clone(&registry),
                    Arc::clone(&poller),
                    Arc::<HandClock>::clone(&clock),
                ),
                done,
            ));
            check
        });
        let logs = if options.collects() {
            Some(collector(&registry, ROUTER).await?)
        } else {
            None
        };
        let web = WebState::new(WebStateConfig {
            default_locale: Locale::En,
            accounts,
            audit,
            roles: Vec::from(built_in_roles()),
            session_idle: Duration::from_hours(240),
            session_absolute: Duration::from_hours(480),
            allowed_origins: vec![ORIGIN.to_owned()],
            cookie_security: CookieSecurity::LoopbackHttp,
            clock: Arc::<HandClock>::clone(&clock),
        })
        .with_log_feeds(logs.as_ref().map(LogService::feeds).unwrap_or_default())
        .with_fleet(FleetServices {
            registry: Arc::clone(&registry),
            poller: Arc::clone(&poller),
            workflow,
            credentials: Arc::new(CredentialStore::new(state.clone(), MasterKey::generate()?)),
            update_check,
            backups: None,
        });
        Ok(Self {
            _directory: directory,
            router: web_router(web.clone()),
            web,
            registry,
            poller,
            clock,
            handle,
            checks,
            logs,
        })
    }

    /// The Web UI state.
    pub(crate) const fn web(&self) -> &WebState {
        &self.web
    }

    /// The registry.
    pub(crate) const fn registry(&self) -> &Arc<RouterRegistry> {
        &self.registry
    }

    /// The shared poller.
    pub(crate) const fn poller(&self) -> &Arc<Poller> {
        &self.poller
    }

    /// The fixture clock.
    pub(crate) const fn clock(&self) -> &Arc<HandClock> {
        &self.clock
    }

    /// The fake router.
    pub(crate) const fn handle(&self) -> &Handle {
        &self.handle
    }

    /// The log collectors, when started.
    pub(crate) const fn logs(&self) -> Option<&LogService> {
        self.logs.as_ref()
    }

    /// The next finished update check, waiting at most 30 s.
    pub(crate) async fn finished(&mut self) -> TestResult<UpdateStatus> {
        Ok(timeout(Duration::from_secs(30), self.checks.recv())
            .await?
            .ok_or("the check reporter closed")?)
    }

    /// Whether an update check finished that was not yet taken.
    pub(crate) fn another_check(&mut self) -> bool {
        self.checks.try_recv().is_ok()
    }

    /// `GET path` as `browser`.
    pub(crate) async fn get(&self, path: &str, browser: &Browser) -> TestResult<Response> {
        Ok(self
            .router
            .clone()
            .oneshot(
                Request::get(path)
                    .header(header::COOKIE, &browser.cookie)
                    .body(Body::empty())?,
            )
            .await?)
    }

    /// Signs `viewer` in.
    pub(crate) async fn login(&self) -> TestResult<Browser> {
        let page = self
            .router
            .clone()
            .oneshot(Request::get("/ui/login").body(Body::empty())?)
            .await?;
        let anonymous = cookie_pair(&page)?;
        let html = text(page).await?;
        let csrf = html
            .split_once("<meta name=\"csrf-token\" content=\"")
            .and_then(|(_, tail)| tail.split_once('"'))
            .map(|(token, _)| token.to_owned())
            .ok_or("login CSRF")?;
        let response = self
            .router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/ui/login")
                    .header(header::COOKIE, anonymous)
                    .header(header::ORIGIN, ORIGIN)
                    .header("sec-fetch-site", "same-origin")
                    .header("x-csrf-token", csrf)
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(format!(
                        "username=viewer&password={}",
                        PASSWORD.replace(' ', "+")
                    )))?,
            )
            .await?;
        Ok(Browser {
            cookie: cookie_pair(&response)?,
        })
    }

    /// Requests whose parser line is exactly `command`.
    pub(crate) fn commands(&self, command: &str) -> usize {
        self.handle
            .request_log()
            .iter()
            .filter(|record| record.command() == Some(command))
            .count()
    }

    /// `POST /rci/show/log` requests: snapshot reads and stream starts.
    pub(crate) fn log_reads(&self) -> usize {
        self.handle
            .request_log()
            .iter()
            .filter(|record| *record.method() == Method::POST && record.path() == "/rci/show/log")
            .count()
    }
}

/// The built-in administrator role.
fn admin() -> TestResult<Role> {
    built_in_roles()
        .into_iter()
        .find(|role| role.name == "admin")
        .ok_or_else(|| "no admin role".into())
}
