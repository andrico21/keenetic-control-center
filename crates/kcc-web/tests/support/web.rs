//! The Web UI over fake routers as a signed-in browser uses it, and what a test reads back:
//! the fake routers, the registry, the audit log and the backups.

extern crate alloc;

use alloc::sync::Arc;
use core::fmt::Write as _;
use std::path::PathBuf;

use axum::{
    Router,
    body::Body,
    http::{Method, Request, StatusCode, header},
    response::Response,
};
use kcc_app::{
    accounts::AccountStore,
    audit::{AuditEntry, AuditLog, receipt::AUDIT_WAIT, verify_chain},
    backups::BackupStore,
    persist::StateStore,
    registry::RouterRegistry,
    role_source::RoleSource,
};
use kcc_testkit::{FakeRouter, FaultInjection, Handle, model::Profile};
use kcc_web::WebState;
use tempfile::TempDir;
use tower::ServiceExt as _;

use super::{
    base::{Frozen, ORIGIN, PASSWORD},
    build::{Setup, admin, master_key},
    outcome::TestResult,
    page::{cookie_pair, form, meta_content, text},
};

/// The profile id of the router pages' fake router.
pub(crate) const ROUTER: &str = "home";

/// The multipart boundary of the uploads.
const BOUNDARY: &str = "kcc-test-boundary";

/// A signed-in browser: its session cookie and CSRF token.
pub(crate) struct Browser {
    /// `kcc_session=<id>`.
    cookie: String,
    /// Token for `X-CSRF-Token`.
    csrf: String,
}

/// The Web UI over fake routers.
#[expect(
    clippy::field_scoped_visibility_modifiers,
    reason = "the builder assembles the fixture"
)]
pub(crate) struct Fixture {
    /// State and credentials.
    pub(super) directory: TempDir,
    /// The Web UI.
    pub(super) router: Router,
    /// The state behind the Web UI.
    pub(super) state: WebState,
    /// The audit log behind it.
    pub(super) audit: AuditLog,
    /// The roles the Web UI reads, as a SIGHUP reload replaces them.
    pub(super) roles: RoleSource,
    /// The accounts, as `users.json` holds them.
    pub(super) accounts: Arc<AccountStore>,
    /// The account and session clock.
    pub(super) clock: Arc<Frozen>,
    /// The registry behind it.
    pub(super) registry: Arc<RouterRegistry>,
    /// The fake routers by profile id, the first one the pages' router.
    pub(super) handles: Vec<(&'static str, Handle)>,
    /// Whether posts carry `HX-Request`, as htmx sends them.
    pub(super) htmx: bool,
}

impl Fixture {
    /// The router pages over a default fake router.
    pub(crate) async fn new() -> TestResult<Self> {
        Self::with_faults(FaultInjection::default()).await
    }

    /// The router pages over a fake router with `faults`.
    pub(crate) async fn with_faults(faults: FaultInjection) -> TestResult<Self> {
        Self::with_router(
            FakeRouter::builder(Profile::default())
                .faults(faults)
                .reached_directly()
                .build()?,
        )
        .await
    }

    /// The router pages over `fake`.
    // NOT cancel-safe: setup creates router and application tasks.
    pub(crate) async fn with_router(fake: FakeRouter) -> TestResult<Self> {
        Setup {
            routers: vec![(ROUTER, fake)],
            ..Setup::default()
        }
        .build()
        .await
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

    /// A same-origin form `POST` of the encoded `form` as `browser`.
    pub(crate) async fn post(
        &self,
        path: &str,
        browser: &Browser,
        form: &str,
    ) -> TestResult<Response> {
        let kind = "application/x-www-form-urlencoded";
        self.post_body(path, browser, (kind, form.as_bytes().to_vec()))
            .await
    }

    /// A same-origin form `POST` of `pairs` as `browser`.
    pub(crate) async fn post_form(
        &self,
        path: &str,
        browser: &Browser,
        pairs: &[(&str, &str)],
    ) -> TestResult<Response> {
        self.post(path, browser, &form(pairs)).await
    }

    /// A same-origin `POST` of `body` with `content_type` as `browser`.
    pub(crate) async fn post_body(
        &self,
        path: &str,
        browser: &Browser,
        (content_type, body): (&str, Vec<u8>),
    ) -> TestResult<Response> {
        let same_origin = Request::builder()
            .method(Method::POST)
            .uri(path)
            .header(header::COOKIE, &browser.cookie)
            .header(header::ORIGIN, ORIGIN)
            .header("sec-fetch-site", "same-origin");
        let request = if self.htmx {
            same_origin.header("hx-request", "true")
        } else {
            same_origin
        };
        self.send(
            request
                .header("x-csrf-token", &browser.csrf)
                .header(header::CONTENT_TYPE, content_type)
                .header(header::CONTENT_LENGTH, body.len())
                .body(Body::from(body))?,
        )
        .await
    }

    /// A same-origin form `POST` of the encoded `form` as `browser` that carries no CSRF
    /// token, as a page of another site would send it with the session cookie.
    pub(crate) async fn post_without_token(
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
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::CONTENT_LENGTH, form.len())
                .body(Body::from(form.to_owned()))?,
        )
        .await
    }

    /// A `multipart/form-data` `POST` of `fields` and, when given, a text `file` named
    /// `startup-config.txt`.
    pub(crate) async fn post_multipart(
        &self,
        path: &str,
        browser: &Browser,
        (fields, file): (&[(&str, &str)], Option<&str>),
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
            csrf: csrf(&text(page).await?)?,
        };
        let pairs = [("username", username), ("password", PASSWORD)];
        let response = self.post_form("/ui/login", &anonymous, &pairs).await?;
        if !self.htmx && response.status() != StatusCode::SEE_OTHER {
            return Err(format!("{username} login: {}", response.status()).into());
        }
        let cookie = cookie_pair(&response)?;
        let account = self
            .send(
                Request::get("/ui/account")
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())?,
            )
            .await?;
        let csrf = csrf(&text(account).await?)?;
        Ok(Browser { cookie, csrf })
    }

    /// The router pages' fake router: the first one served.
    ///
    /// # Panics
    ///
    /// When the fixture serves no router.
    #[expect(
        clippy::indexing_slicing,
        reason = "only the router pages ask, and their fixture always serves a router"
    )]
    pub(crate) fn handle(&self) -> &Handle {
        &self.handles[0].1
    }

    /// The fake router `id`.
    pub(crate) fn router(&self, id: &str) -> TestResult<&Handle> {
        self.handles
            .iter()
            .find(|(known, _)| *known == id)
            .map(|(_, handle)| handle)
            .ok_or_else(|| format!("no fake router {id}").into())
    }

    /// The requests every fake router has received so far, by router.
    pub(crate) fn request_counts(&self) -> Vec<(&'static str, u64)> {
        self.handles
            .iter()
            .map(|(id, handle)| (*id, handle.request_count()))
            .collect()
    }

    /// Waits at most [`AUDIT_WAIT`] until the audit writer wrote every queued entry;
    /// returns how many were still queued then.
    // cancel-safe: waiting only observes the writer's progress.
    pub(crate) async fn audit_flushed(&self) -> usize {
        self.audit.flush(AUDIT_WAIT).await
    }

    /// The state behind the Web UI.
    pub(crate) const fn state(&self) -> &WebState {
        &self.state
    }

    /// The roles the Web UI reads.
    pub(crate) const fn roles(&self) -> &RoleSource {
        &self.roles
    }

    /// The accounts.
    pub(crate) fn accounts(&self) -> &AccountStore {
        &self.accounts
    }

    /// The account and session clock.
    pub(crate) fn clock(&self) -> &Frozen {
        &self.clock
    }

    /// The registry, for direct router access in test setup.
    pub(crate) fn registry(&self) -> &RouterRegistry {
        &self.registry
    }

    /// Gives router `id` the display name `label`.
    // NOT cancel-safe: the registry may write `routers.json` before the future is dropped.
    pub(crate) async fn label(&self, id: &str, label: &str) -> TestResult {
        let mut profile = self.registry.get(id)?.profile;
        profile.label = Some(label.to_owned());
        self.registry.update(&admin()?, profile).await?;
        Ok(())
    }

    /// The audit log so far, verified.
    pub(crate) fn audit(&self) -> TestResult<Vec<AuditEntry>> {
        Ok(verify_chain(&self.state_dir())?)
    }

    /// Whether the audit log has `action` ending as `outcome`.
    pub(crate) fn audited(&self, action: &str, outcome: &str) -> TestResult<bool> {
        Ok(self
            .audit()?
            .iter()
            .any(|entry| entry.action == action && entry.outcome == outcome))
    }

    /// The outcomes of the audit entries of `action`, in order.
    pub(crate) fn outcomes(&self, action: &str) -> TestResult<Vec<String>> {
        Ok(self
            .audit()?
            .into_iter()
            .filter(|entry| entry.action == action)
            .map(|entry| entry.outcome)
            .collect())
    }

    /// The backup store of the fixture's state.
    pub(crate) fn backup_store(&self) -> TestResult<BackupStore> {
        Ok(BackupStore::new(
            StateStore::open(&self.state_dir())?,
            master_key(),
        ))
    }

    /// How many backups the router pages' router has.
    pub(crate) fn backups(&self) -> TestResult<usize> {
        Ok(self.backup_store()?.list(ROUTER)?.len())
    }

    /// The fixture's directory: state and router password file.
    pub(crate) fn directory(&self) -> PathBuf {
        self.directory.path().to_path_buf()
    }

    /// The state directory.
    pub(crate) fn state_dir(&self) -> PathBuf {
        self.directory.path().join("state")
    }
}

/// The CSRF token of a rendered page.
fn csrf(page: &str) -> TestResult<String> {
    meta_content(page, "csrf-token").ok_or_else(|| "no CSRF token".into())
}
