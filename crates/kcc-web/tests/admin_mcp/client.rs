//! A signed-in browser on the MCP settings page: its requests and what it reads back.

use core::{fmt::Write as _, time::Duration};

use axum::{
    body::Body,
    http::{Method, Request, StatusCode, header},
    response::Response,
};
use tokio::{task::yield_now, time::timeout};
use tower::ServiceExt as _;

use crate::{
    fixture::Mcp,
    support::{
        base::{ORIGIN, PASSWORD},
        outcome::TestResult,
        page::{cookie_pair, form, meta_content, text},
    },
};

/// The page.
pub(crate) const PAGE: &str = "/ui/admin/mcp";

/// The multipart boundary of the uploads.
const BOUNDARY: &str = "kcc-mcp-boundary";

/// Marks the status fragment while it keeps polling.
pub(crate) const POLLING: &str = "every 2s";

/// Real time a restart may take to end: the restart's audit entry waits at most 30 s.
const RESTART_BOUND: Duration = Duration::from_secs(60);

/// A signed-in browser: its session cookie and CSRF token.
pub(crate) struct Browser {
    /// `kcc_session=<id>`.
    cookie: String,
    /// Token for `X-CSRF-Token`; empty to send none.
    csrf: String,
}

impl Browser {
    /// The same browser without its CSRF token.
    pub(crate) fn tokenless(&self) -> Self {
        Self {
            cookie: self.cookie.clone(),
            csrf: String::new(),
        }
    }
}

#[expect(
    clippy::multiple_inherent_impl,
    reason = "the requests live beside the browser they use; the fixture file builds the page"
)]
impl Mcp {
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

    /// An htmx `POST` of `body` with `kind` to `path` as `browser`.
    async fn post_body(
        &self,
        path: &str,
        browser: &Browser,
        (kind, body): (&str, Vec<u8>),
    ) -> TestResult<Response> {
        let mut request = Request::builder()
            .method(Method::POST)
            .uri(path)
            .header(header::COOKIE, &browser.cookie)
            .header(header::ORIGIN, ORIGIN)
            .header("sec-fetch-site", "same-origin")
            .header("hx-request", "true")
            .header(header::CONTENT_TYPE, kind)
            .header(header::CONTENT_LENGTH, body.len());
        if !browser.csrf.is_empty() {
            request = request.header("x-csrf-token", &browser.csrf);
        }
        self.send(request.body(Body::from(body))?).await
    }

    /// An htmx form post of `pairs` to `path` as `browser`.
    pub(crate) async fn post(
        &self,
        path: &str,
        browser: &Browser,
        pairs: &[(&str, &str)],
    ) -> TestResult<Response> {
        let kind = "application/x-www-form-urlencoded";
        self.post_body(path, browser, (kind, form(pairs).into_bytes()))
            .await
    }

    /// An htmx form post of `pairs` to the page, answered as text with its status.
    pub(crate) async fn save(
        &self,
        browser: &Browser,
        pairs: &[(&str, &str)],
    ) -> TestResult<(StatusCode, String)> {
        let response = self.post(PAGE, browser, pairs).await?;
        let status = response.status();
        Ok((status, text(response).await?))
    }

    /// A `multipart/form-data` upload to `path` of `fields` and a `file` holding `bytes`.
    pub(crate) async fn upload(
        &self,
        path: &str,
        browser: &Browser,
        (fields, bytes): (&[(&str, &str)], &[u8]),
    ) -> TestResult<Response> {
        let mut head = String::new();
        for (name, value) in fields {
            write!(
                head,
                "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
            )?;
        }
        write!(
            head,
            "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"ca.pem\"\r\nContent-Type: application/x-pem-file\r\n\r\n"
        )?;
        let mut body = head.into_bytes();
        body.extend_from_slice(bytes);
        body.extend_from_slice(format!("\r\n--{BOUNDARY}--\r\n").as_bytes());
        let kind = format!("multipart/form-data; boundary={BOUNDARY}");
        self.post_body(path, browser, (&kind, body)).await
    }

    /// The status fragment as `browser` once it stops polling, or an error after
    /// [`RESTART_BOUND`] of real time.
    ///
    /// The stand-in answers at once, but the restart's task ends only after its audit
    /// entry is written on the blocking pool, which a loaded machine delays by any number
    /// of turns of this runtime: the wait is bounded by time, not by turns.
    pub(crate) async fn settled(&self, browser: &Browser) -> TestResult<String> {
        let polled = timeout(RESTART_BOUND, async {
            loop {
                let fragment = self.html(&status_path(), browser).await?;
                if !fragment.contains(POLLING) {
                    return Ok(fragment);
                }
                yield_now().await;
            }
        })
        .await;
        polled.map_err(|_elapsed| "the restart never ended")?
    }

    /// Signs `username` in.
    pub(crate) async fn login(&self, username: &str) -> TestResult<Browser> {
        let response = self.sign_in(username, PASSWORD).await?;
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

    /// The answer to signing `username` in with `password`.
    pub(crate) async fn sign_in(&self, username: &str, password: &str) -> TestResult<Response> {
        let page = self
            .send(Request::get("/ui/login").body(Body::empty())?)
            .await?;
        let cookie = cookie_pair(&page)?;
        let csrf = meta_content(&text(page).await?, "csrf-token").ok_or("login CSRF")?;
        self.send(
            Request::builder()
                .method(Method::POST)
                .uri("/ui/login")
                .header(header::COOKIE, &cookie)
                .header(header::ORIGIN, ORIGIN)
                .header("sec-fetch-site", "same-origin")
                .header("x-csrf-token", &csrf)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form(&[
                    ("username", username),
                    ("password", password),
                ])))?,
        )
        .await
    }
}

/// The status fragment's path, polling with no deadline in sight.
pub(crate) fn status_path() -> String {
    format!("{PAGE}/status?until={}", u64::MAX)
}
