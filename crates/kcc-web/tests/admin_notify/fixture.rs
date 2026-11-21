//! The notifications page over a fleet without routers, its administration services and,
//! when a test asks for one, a stub of the running notifier.

extern crate alloc;

use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};
use std::{
    fs,
    path::Path,
    sync::{Mutex, PoisonError},
};

use axum::{
    Router,
    body::Body,
    http::{Method, Request, StatusCode, header},
    response::Response,
};
use kcc_app::{
    audit::AuditEntry,
    mcp_settings::{EnvOverrides, McpBase},
    permissions::{Permission, Role},
    persist::StateStore,
    settings::Config,
};
use kcc_web::{
    admin::{AdminServices, ServerFacts},
    admin_notify::{NotifyControl, NotifyStatus, NotifyTestError, TestSend},
    web_router,
};
use tower::ServiceExt as _;

use crate::support::{
    base::{ORIGIN, PASSWORD},
    build::{Setup, Wiring},
    outcome::TestResult,
    page::{cookie_pair, form, meta_content, text},
    web::Fixture,
};

/// A stand-in for the running notifier: a fixed status and test answer, and a record of
/// what the page asked of it.
#[derive(Debug, Default)]
pub(crate) struct Stub {
    /// What [`NotifyControl::status`] reports.
    status: NotifyStatus,
    /// The test send's failure, `None` for sent.
    answer: Option<NotifyTestError>,
    /// The chats test messages were sent to, in order.
    sends: Mutex<Vec<String>>,
    /// How many reloads the page asked for.
    reloads: AtomicUsize,
}

impl Stub {
    /// A notifier reporting `status` that answers every test send with `answer`.
    pub(crate) fn new(status: NotifyStatus, answer: Option<NotifyTestError>) -> Arc<Self> {
        Arc::new(Self {
            status,
            answer,
            ..Self::default()
        })
    }

    /// The chats test messages were sent to.
    pub(crate) fn sends(&self) -> Vec<String> {
        self.sends
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// How many reloads the page asked for.
    pub(crate) fn reloads(&self) -> usize {
        self.reloads.load(Ordering::SeqCst)
    }
}

impl NotifyControl for Stub {
    fn status(&self) -> NotifyStatus {
        self.status.clone()
    }

    fn send_test<'send>(&'send self, chat: &'send str) -> TestSend<'send> {
        self.sends
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(chat.to_owned());
        let answer = self.answer;
        Box::pin(async move { answer.map_or(Ok(()), Err) })
    }

    fn reload(&self) {
        let _: usize = self.reloads.fetch_add(1, Ordering::SeqCst);
    }
}

/// A signed-in browser: its session cookie and CSRF token.
pub(crate) struct Browser {
    /// `kcc_session=<id>`.
    cookie: String,
    /// Token for `X-CSRF-Token`.
    csrf: String,
}

/// The Web UI with the notifications page.
pub(crate) struct Notify {
    /// The fleet fixture: state directory, accounts and audit log.
    web: Fixture,
    /// The Web UI with the administration services and the notifier attached.
    router: Router,
    /// The state directory.
    store: StateStore,
}

impl Notify {
    /// The page without a running notifier, or with `control` attached. Accounts:
    /// `admin`, `operator`, `viewer`, `una` (Read and `ManageUsers`) and `nina` (Read and
    /// `ManageNotifications`).
    // NOT cancel-safe: setup starts the fleet's tasks.
    pub(crate) async fn build(control: Option<Arc<Stub>>) -> TestResult<Self> {
        let every = || vec!["*".to_owned()];
        let mut setup = Setup {
            wiring: Wiring::Fleet,
            ..Setup::default()
        };
        setup.roles.extend([
            Role::new(
                "useradmin".to_owned(),
                [Permission::Read, Permission::ManageUsers],
                every(),
            ),
            Role::new(
                "notifier".to_owned(),
                [Permission::Read, Permission::ManageNotifications],
                every(),
            ),
        ]);
        setup
            .accounts
            .extend([("una", "useradmin", None), ("nina", "notifier", None)]);
        let web = setup.build().await?;
        let store = StateStore::open(&web.state_dir())?;
        let mut state = web.state().clone().with_admin(AdminServices {
            state: store.clone(),
            reload: None,
            server: ServerFacts::from_config(
                "9.9.9".to_owned(),
                &Config::default(),
                &McpBase::default().effective(&store)?,
            ),
            mcp: McpBase::new(&Config::default(), &EnvOverrides::default()),
        });
        if let Some(stub) = control {
            let attached: Arc<dyn NotifyControl> = stub;
            state = state.with_notify(attached);
        }
        Ok(Self {
            router: web_router(state),
            store,
            web,
        })
    }

    /// The state directory.
    pub(crate) const fn store(&self) -> &StateStore {
        &self.store
    }

    /// Sends one request.
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

    /// The page at `path` as `browser`, as text; it must answer 200.
    pub(crate) async fn html(&self, path: &str, browser: &Browser) -> TestResult<String> {
        let response = self.get(path, browser).await?;
        if response.status() != StatusCode::OK {
            return Err(format!("GET {path}: {}", response.status()).into());
        }
        text(response).await
    }

    /// The same post without the CSRF token.
    pub(crate) async fn post_without_csrf(
        &self,
        path: &str,
        browser: &Browser,
        pairs: &[(&str, &str)],
    ) -> TestResult<Response> {
        let tokenless = Browser {
            cookie: browser.cookie.clone(),
            csrf: String::new(),
        };
        self.post(path, &tokenless, pairs).await
    }

    /// An htmx form post of `pairs` to `path` as `browser`, with its CSRF token unless it
    /// has none.
    pub(crate) async fn post(
        &self,
        path: &str,
        browser: &Browser,
        pairs: &[(&str, &str)],
    ) -> TestResult<Response> {
        let mut request = Request::builder()
            .method(Method::POST)
            .uri(path)
            .header(header::COOKIE, &browser.cookie)
            .header(header::ORIGIN, ORIGIN)
            .header("sec-fetch-site", "same-origin")
            .header("hx-request", "true")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        if !browser.csrf.is_empty() {
            request = request.header("x-csrf-token", &browser.csrf);
        }
        self.send(request.body(Body::from(form(pairs)))?).await
    }

    /// Signs `username` in.
    pub(crate) async fn login(&self, username: &str) -> TestResult<Browser> {
        let page = self
            .send(Request::get("/ui/login").body(Body::empty())?)
            .await?;
        let anonymous = Browser {
            cookie: cookie_pair(&page)?,
            csrf: meta_content(&text(page).await?, "csrf-token").ok_or("login CSRF")?,
        };
        let response = self
            .send(
                Request::builder()
                    .method(Method::POST)
                    .uri("/ui/login")
                    .header(header::COOKIE, &anonymous.cookie)
                    .header(header::ORIGIN, ORIGIN)
                    .header("sec-fetch-site", "same-origin")
                    .header("x-csrf-token", &anonymous.csrf)
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(form(&[
                        ("username", username),
                        ("password", PASSWORD),
                    ])))?,
            )
            .await?;
        if response.status() != StatusCode::SEE_OTHER {
            return Err(format!("{username} login: {}", response.status()).into());
        }
        let cookie = cookie_pair(&response)?;
        let signed_in = Browser {
            cookie,
            csrf: String::new(),
        };
        let account = self.html("/ui/account", &signed_in).await?;
        Ok(Browser {
            csrf: meta_content(&account, "csrf-token").ok_or("account CSRF")?,
            ..signed_in
        })
    }

    /// The audit entries of `action`, once every queued entry is written.
    pub(crate) async fn audited(&self, action: &str) -> TestResult<Vec<AuditEntry>> {
        let queued = self.web.audit_flushed().await;
        if queued != 0 {
            return Err(format!("{queued} audit entries still queued").into());
        }
        Ok(self
            .web
            .audit()?
            .into_iter()
            .filter(|entry| entry.action == action)
            .collect())
    }

    /// Whether any file below the state directory holds `needle`.
    pub(crate) fn state_holds(&self, needle: &str) -> TestResult<bool> {
        holds(self.store.dir(), needle.as_bytes())
    }
}

/// Whether any file below `dir` holds `needle`.
fn holds(dir: &Path, needle: &[u8]) -> TestResult<bool> {
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        let found = if path.is_dir() {
            holds(&path, needle)?
        } else {
            fs::read(&path)?
                .windows(needle.len())
                .any(|window| window == needle)
        };
        if found {
            return Ok(true);
        }
    }
    Ok(false)
}
