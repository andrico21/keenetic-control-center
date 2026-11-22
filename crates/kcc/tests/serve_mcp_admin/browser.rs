//! A signed-in browser of the server's Web UI: sign-in, pages and same-origin form posts.
#![expect(
    clippy::missing_errors_doc,
    reason = "test support returns the boxed error of whatever step failed"
)]

use reqwest::{Client, Response, StatusCode, header};
use url::form_urlencoded;

use crate::fixture::TestResult;

/// A signed-in browser.
pub(crate) struct Browser {
    /// `name=value` of the session cookie.
    cookie: String,
    /// Token for `X-CSRF-Token`.
    csrf: String,
    /// The listener's base URL.
    base: String,
}

impl Browser {
    /// `name` signed in at `base` with `password`.
    pub(crate) async fn sign_in(
        client: &Client,
        base: &str,
        (name, password): (&str, &str),
    ) -> TestResult<Self> {
        let login = client.get(format!("{base}/ui/login")).send().await?;
        let anonymous = Self {
            cookie: cookie_pair(&login)?,
            csrf: csrf(&login.text().await?)?,
            base: base.to_owned(),
        };
        let pairs = [("username", name), ("password", password)];
        let response = anonymous.post(client, "/ui/login", &pairs).await?;
        if response.status() != StatusCode::SEE_OTHER {
            return Err(format!("{name} could not sign in: {}", response.status()).into());
        }
        let cookie = cookie_pair(&response)?;
        let account = client
            .get(format!("{base}/ui/account"))
            .header(header::COOKIE, &cookie)
            .send()
            .await?;
        Ok(Self {
            csrf: csrf(&account.text().await?)?,
            cookie,
            base: base.to_owned(),
        })
    }

    /// `GET path` as text.
    pub(crate) async fn get(&self, client: &Client, path: &str) -> TestResult<String> {
        Ok(client
            .get(format!("{}{path}", self.base))
            .header(header::COOKIE, &self.cookie)
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?)
    }

    /// A same-origin form `POST` of `pairs` to `path`.
    pub(crate) async fn post(
        &self,
        client: &Client,
        path: &str,
        pairs: &[(&str, &str)],
    ) -> TestResult<Response> {
        let body = {
            let mut form = form_urlencoded::Serializer::new(String::new());
            for (name, value) in pairs {
                let _: &mut form_urlencoded::Serializer<'_, String> = form.append_pair(name, value);
            }
            form.finish()
        };
        Ok(client
            .post(format!("{}{path}", self.base))
            .header(header::COOKIE, &self.cookie)
            .header(header::ORIGIN, &self.base)
            .header("sec-fetch-site", "same-origin")
            .header("x-csrf-token", &self.csrf)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(body)
            .send()
            .await?)
    }
}

/// The `name=value` pair of the response's `Set-Cookie`.
fn cookie_pair(response: &Response) -> TestResult<String> {
    response
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::to_owned)
        .ok_or_else(|| "missing Set-Cookie".into())
}

/// The CSRF token of a rendered page.
fn csrf(html: &str) -> TestResult<String> {
    html.split_once("<meta name=\"csrf-token\" content=\"")
        .and_then(|(_, tail)| tail.split_once('"'))
        .map(|(token, _)| token.to_owned())
        .ok_or_else(|| "no CSRF token".into())
}
