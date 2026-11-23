//! The browser side of the flow: the consent page without a session shows the login with
//! the request id, the sign-in resumes at the consent page, and approve or deny post with
//! the session's CSRF token.
#![expect(
    clippy::missing_errors_doc,
    reason = "test support returns the boxed error of whatever step failed"
)]

use reqwest::{Response, StatusCode, header};

use crate::{
    fixture::{Fixture, Server, TestResult},
    flow::{form, location},
};

/// A browser session at the server.
pub(crate) struct Browser {
    /// `name=value` of the session cookie.
    cookie: String,
    /// Token for `X-CSRF-Token`.
    csrf: String,
    /// The listener's base URL.
    base: String,
}

/// The `HX-Redirect` of `response`.
pub(crate) fn hx_redirect(response: &Response) -> Option<String> {
    response
        .headers()
        .get("hx-redirect")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

/// The `name=value` pair of the response's `Set-Cookie`.
pub(crate) fn cookie_pair(response: &Response) -> TestResult<String> {
    response
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::to_owned)
        .ok_or_else(|| "missing Set-Cookie".into())
}

/// The CSRF token of a rendered page.
pub(crate) fn csrf(html: &str) -> TestResult<String> {
    html.split_once("<meta name=\"csrf-token\" content=\"")
        .and_then(|(_, tail)| tail.split_once('"'))
        .map(|(token, _)| token.to_owned())
        .ok_or_else(|| "no CSRF token".into())
}

/// The value of the hidden field `consent` of a rendered login form.
pub(crate) fn resume_field(html: &str) -> Option<String> {
    html.split_once("name=\"consent\" value=\"")
        .and_then(|(_, tail)| tail.split_once('"'))
        .map(|(value, _)| value.to_owned())
}

impl Browser {
    /// Opens the consent page of `id` without a session (the login page with the request
    /// id), signs in as `name` with the id, follows the resume to the consent page.
    pub(crate) async fn resume(
        fixture: &Fixture,
        server: &Server,
        (name, password): (&str, &str),
        id: &str,
    ) -> TestResult<Self> {
        let base = server.base();
        let page = fixture
            .http()
            .get(format!("{base}/ui/oauth/consent?request={id}"))
            .send()
            .await?;
        let cookie = cookie_pair(&page)?;
        let html = page.text().await?;
        let field = resume_field(&html).ok_or("the login page carries no request id")?;
        let anonymous = Self {
            cookie,
            csrf: csrf(&html)?,
            base: base.clone(),
        };
        let pairs = [
            ("username", name),
            ("password", password),
            ("consent", field.as_str()),
        ];
        let signed = anonymous.post(fixture, "/ui/login", &pairs).await?;
        let to = location(&signed).ok_or_else(|| format!("login answered {}", signed.status()))?;
        if to != format!("/ui/oauth/consent?request={id}") {
            return Err(format!("login resumed at {to}").into());
        }
        let session = cookie_pair(&signed)?;
        let consent = fixture
            .http()
            .get(format!("{base}{to}"))
            .header(header::COOKIE, &session)
            .send()
            .await?;
        if consent.status() != StatusCode::OK {
            return Err(format!("the consent page answered {}", consent.status()).into());
        }
        Ok(Self {
            csrf: csrf(&consent.text().await?)?,
            cookie: session,
            base,
        })
    }

    /// `GET path` with the session.
    pub(crate) async fn get(&self, fixture: &Fixture, path: &str) -> TestResult<Response> {
        Ok(fixture
            .http()
            .get(format!("{}{path}", self.base))
            .header(header::COOKIE, &self.cookie)
            .send()
            .await?)
    }

    /// An htmx `POST` of `decision` (`approve` or `deny`) on the request `id`.
    pub(crate) async fn decide(
        &self,
        fixture: &Fixture,
        id: &str,
        decision: &str,
    ) -> TestResult<Response> {
        Ok(fixture
            .http()
            .post(format!("{}/ui/oauth/consent/{decision}", self.base))
            .header(header::COOKIE, &self.cookie)
            .header(header::ORIGIN, &self.base)
            .header("sec-fetch-site", "same-origin")
            .header("x-csrf-token", &self.csrf)
            .header("hx-request", "true")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(form(&[("request", id)]))
            .send()
            .await?)
    }

    /// A same-origin htmx form `POST` of `pairs` to `path`.
    pub(crate) async fn post(
        &self,
        fixture: &Fixture,
        path: &str,
        pairs: &[(&str, &str)],
    ) -> TestResult<Response> {
        Ok(fixture
            .http()
            .post(format!("{}{path}", self.base))
            .header(header::COOKIE, &self.cookie)
            .header(header::ORIGIN, &self.base)
            .header("sec-fetch-site", "same-origin")
            .header("x-csrf-token", &self.csrf)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(form(pairs))
            .send()
            .await?)
    }
}
