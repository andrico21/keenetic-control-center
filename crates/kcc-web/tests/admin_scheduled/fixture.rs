//! The scheduled actions page over one fake router (`home`), its administration services
//! and, when a test asks for one, a stub of the running scheduler ([`Stub`]).

extern crate alloc;

use alloc::sync::Arc;

use axum::{
    Router,
    body::Body,
    http::{Method, Request, StatusCode, header},
    response::Response,
};
use kcc_app::{
    audit::AuditEntry,
    permissions::{Permission, Role},
    persist::StateStore,
    schedules::{
        model::{Action, NewSchedule, Owner, Schedule, names::ScheduleName},
        store::ScheduleStore,
        time::{DaySet, WeeklyTime, ZoneName},
    },
    settings::Config,
};
use kcc_testkit::{FakeRouter, model::Profile};
use kcc_web::{
    admin::{AdminServices, ServerFacts},
    admin_scheduled::ScheduleControl,
    web_router,
};
use tower::ServiceExt as _;

use crate::{
    stub::Stub,
    support::{
        base::{ORIGIN, PASSWORD},
        build::{Setup, admin},
        outcome::TestResult,
        page::{cookie_pair, form, meta_content, text},
        web::Fixture,
    },
};

/// The page.
pub(crate) const PAGE: &str = "/ui/admin/scheduled";

/// A signed-in browser: its session cookie and CSRF token.
pub(crate) struct Browser {
    /// `kcc_session=<id>`.
    cookie: String,
    /// Token for `X-CSRF-Token`.
    csrf: String,
}

/// The Web UI with the scheduled actions page over the fake router `home`.
pub(crate) struct Scheduled {
    /// The fleet fixture: state directory, fake router, accounts and audit log.
    web: Fixture,
    /// The Web UI with the administration services and the scheduler attached.
    router: Router,
    /// The state directory.
    store: StateStore,
}

impl Scheduled {
    /// The page without a running scheduler, or with `control` attached. Accounts:
    /// `admin`, `operator`, `viewer`, `una` (Read and `ManageUsers`) and `sam` (Read,
    /// Write and `ManageSchedules`, no `Destructive`).
    // NOT cancel-safe: setup starts the fake router and the fleet's tasks.
    pub(crate) async fn build(control: Option<Arc<Stub>>) -> TestResult<Self> {
        let every = || vec!["*".to_owned()];
        let fake = FakeRouter::builder(Profile::default())
            .reached_directly()
            .build()?;
        let mut setup = Setup {
            routers: vec![("home", fake)],
            ..Setup::default()
        };
        setup.roles.extend([
            Role::new(
                "useradmin".to_owned(),
                [Permission::Read, Permission::ManageUsers],
                every(),
            ),
            Role::new(
                "scheduler".to_owned(),
                [
                    Permission::Read,
                    Permission::Write,
                    Permission::ManageSchedules,
                ],
                every(),
            ),
        ]);
        setup
            .accounts
            .extend([("una", "useradmin", None), ("sam", "scheduler", None)]);
        let web = setup.build().await?;
        let store = StateStore::open(&web.state_dir())?;
        let mut state = web.state().clone().with_admin(AdminServices {
            state: store.clone(),
            reload: None,
            server: ServerFacts::from_config("9.9.9".to_owned(), &Config::default()),
        });
        if let Some(stub) = control {
            let attached: Arc<dyn ScheduleControl> = stub;
            state = state.with_schedules(attached);
        }
        Ok(Self {
            router: web_router(state),
            store,
            web,
        })
    }

    /// The fleet fixture.
    pub(crate) const fn web(&self) -> &Fixture {
        &self.web
    }

    /// The schedules as stored.
    pub(crate) fn schedules(&self) -> TestResult<Vec<Schedule>> {
        Ok(ScheduleStore::new(self.store.clone()).list(&admin()?)?)
    }

    /// The state directory.
    pub(crate) const fn store(&self) -> &StateStore {
        &self.store
    }

    /// Stores `action` on `home` every day at 03:00 UTC as `name`, owned by `admin`.
    pub(crate) fn stored(&self, name: &str, action: Action) -> TestResult<Schedule> {
        let when = WeeklyTime::new(
            DaySet::from_names(["mon", "tue", "wed", "thu", "fri", "sat", "sun"])?,
            3,
            0,
            ZoneName::parse("UTC")?,
        )?;
        let new = NewSchedule::new(ScheduleName::parse(name)?, "home".to_owned(), when, action);
        let owner = Owner::Web {
            username: "admin".to_owned(),
        };
        Ok(ScheduleStore::new(self.store.clone()).create(&admin()?, new, owner, 1_700_000_000)?)
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
        let signed_in = Browser {
            cookie: cookie_pair(&response)?,
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
}
