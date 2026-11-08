//! The Web UI over the fake routers of the migration wizard.
//!
//! `giga` (KN-1010) is the source, `ultra` (KN-1811 in router mode) the target, and
//! `legacy` (KN-1811 on 4.3) a documentation-based firmware line; accounts sign in through
//! real sessions.
#![expect(
    clippy::missing_errors_doc,
    reason = "test support is not rendered API documentation; every error fails the test"
)]

use alloc::sync::Arc;
use core::{error::Error, fmt::Write as _, time::Duration};
use std::path::PathBuf;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Method, Request, header},
    response::Response,
};
use kcc_app::{
    accounts::Clock,
    audit::{AuditEntry, AuditLog, verify_chain},
    backups::BackupStore,
    credentials::CredentialStore,
    jobs::JobRunner,
    persist::StateStore,
    poller::Poller,
    registry::RouterRegistry,
    secrets::MasterKey,
    settings::OutboundConfig,
    workflow::ChangeWorkflow,
};
use kcc_i18n::locale::Locale;
use kcc_testkit::{FaultInjection, Handle};
use kcc_web::{
    WebState, WebStateConfig, fleet::FleetServices, session::CookieSecurity, web_router,
};
use tempfile::TempDir;
use tower::ServiceExt as _;

use crate::setup;

/// Fallible test result.
pub(crate) type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

/// Largest response body a test reads.
const BODY_CAP: usize = 0x0100_0000;

/// The only browser origin the fixture accepts.
const ORIGIN: &str = "http://127.0.0.1:8080";

/// Password of every fixture account.
const PASSWORD: &str = "correct horse battery staple";

/// The multipart boundary of the step-1 form.
const BOUNDARY: &str = "kcc-wizard-boundary";

/// A frozen account and session clock.
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

/// The Web UI over the fake routers.
pub(crate) struct Fixture {
    /// State and credentials.
    directory: TempDir,
    /// The Web UI.
    router: Router,
    /// The registry behind it.
    registry: Arc<RouterRegistry>,
    /// The fake routers by profile id.
    handles: Vec<(&'static str, Handle)>,
}

impl Fixture {
    /// The fixture with a fault-free target.
    pub(crate) async fn new() -> TestResult<Self> {
        Self::with_target_faults(FaultInjection::default()).await
    }

    /// The fixture whose target `ultra` has `faults`.
    pub(crate) async fn with_target_faults(faults: FaultInjection) -> TestResult<Self> {
        let directory = TempDir::new()?;
        let state = StateStore::open(&directory.path().join("state"))?;
        let clock: Arc<dyn Clock> = Arc::new(FrozenClock);
        let accounts = setup::accounts(&state, &clock, PASSWORD)?;
        let mut outbound = OutboundConfig::default();
        outbound.allow_loopback = true;
        let registry = Arc::new(RouterRegistry::new(state.clone(), &[], &outbound)?);
        let handles = setup::routers(directory.path(), &registry, faults).await?;
        let audit = AuditLog::spawn(&state)?;
        let backups = Arc::new(BackupStore::new(state.clone(), master_key()));
        let workflow =
            ChangeWorkflow::new(state.clone(), Arc::clone(&registry), backups, audit.clone());
        let jobs = JobRunner::open(state.clone(), Arc::clone(&registry)).await?;
        let web = WebState::new(WebStateConfig {
            default_locale: Locale::En,
            accounts,
            audit,
            roles: setup::roles(),
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
            backups: None,
        })
        .with_jobs(jobs);
        Ok(Self {
            directory,
            router: web_router(web),
            registry,
            handles,
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

    /// A same-origin htmx `POST` of `body` with `content_type` as `browser`.
    pub(crate) async fn post_body(
        &self,
        path: &str,
        browser: &Browser,
        (content_type, body): (&str, Vec<u8>),
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
                .header(header::CONTENT_TYPE, content_type)
                .body(Body::from(body))?,
        )
        .await
    }

    /// A form `POST` of `pairs` as `browser`.
    pub(crate) async fn post(
        &self,
        path: &str,
        browser: &Browser,
        pairs: &[(&str, &str)],
    ) -> TestResult<Response> {
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(pairs)
            .finish();
        let kind = "application/x-www-form-urlencoded";
        self.post_body(path, browser, (kind, body.into_bytes()))
            .await
    }

    /// The step-1 `multipart/form-data` `POST` of `fields` and an optional `file`.
    pub(crate) async fn post_source(
        &self,
        path: &str,
        browser: &Browser,
        fields: &[(&str, &str)],
        file: Option<&str>,
    ) -> TestResult<Response> {
        let mut body = String::new();
        for (name, value) in fields {
            write!(
                body,
                "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
            )?;
        }
        if let Some(text) = file {
            write!(
                body,
                "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"startup-config.txt\"\r\nContent-Type: text/plain\r\n\r\n{text}\r\n"
            )?;
        }
        write!(body, "--{BOUNDARY}--\r\n")?;
        let kind = format!("multipart/form-data; boundary={BOUNDARY}");
        self.post_body(path, browser, (&kind, body.into_bytes()))
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
        let response = self
            .post(
                "/ui/login",
                &anonymous,
                &[("username", username), ("password", PASSWORD)],
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

    /// The fake router `id`.
    pub(crate) fn handle(&self, id: &str) -> TestResult<&Handle> {
        self.handles
            .iter()
            .find(|(known, _)| *known == id)
            .map(|(_, handle)| handle)
            .ok_or_else(|| format!("no fake router {id}").into())
    }

    /// The registry, for direct router access in test setup.
    pub(crate) fn registry(&self) -> &RouterRegistry {
        &self.registry
    }

    /// The audit log so far, verified.
    pub(crate) fn audit(&self) -> TestResult<Vec<AuditEntry>> {
        Ok(verify_chain(&self.state_dir())?)
    }

    /// The backup store of the fixture's state.
    pub(crate) fn backups(&self) -> TestResult<BackupStore> {
        Ok(BackupStore::new(
            StateStore::open(&self.state_dir())?,
            master_key(),
        ))
    }

    /// The state directory.
    pub(crate) fn state_dir(&self) -> PathBuf {
        self.directory.path().join("state")
    }
}

/// The fixture's backup key.
fn master_key() -> MasterKey {
    MasterKey::from_bytes([7_u8; 32])
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
