//! A browser for the server's Web UI: sign-in, pages, and same-origin form posts.
#![expect(
    clippy::missing_errors_doc,
    reason = "test support returns the boxed error of whatever step failed"
)]

use reqwest::{Client, Response, StatusCode, header};
use url::form_urlencoded;

use crate::support::{PASSWORD, TestResult};

/// A signed-in browser: its session cookie and CSRF token.
pub(crate) struct Browser {
    /// `name=value` of the session cookie.
    cookie: String,
    /// Token for `X-CSRF-Token`.
    csrf: String,
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

impl Browser {
    /// Signs `name` in at `base`.
    pub(crate) async fn sign_in(client: &Client, base: &str, name: &str) -> TestResult<Self> {
        let login = client.get(format!("{base}/ui/login")).send().await?;
        let anonymous = Self {
            cookie: cookie_pair(&login)?,
            csrf: csrf(&login.text().await?)?,
        };
        let response = anonymous
            .post(
                client,
                base,
                ("/ui/login", &[("username", name), ("password", PASSWORD)]),
            )
            .await?;
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
        })
    }

    /// `GET path`.
    pub(crate) async fn get(
        &self,
        client: &Client,
        base: &str,
        path: &str,
    ) -> TestResult<Response> {
        Ok(client
            .get(format!("{base}{path}"))
            .header(header::COOKIE, &self.cookie)
            .send()
            .await?)
    }

    /// A same-origin form `POST` of `pairs` to `path`.
    pub(crate) async fn post(
        &self,
        client: &Client,
        base: &str,
        (path, pairs): (&str, &[(&str, &str)]),
    ) -> TestResult<Response> {
        let body = {
            let mut form = form_urlencoded::Serializer::new(String::new());
            for (name, value) in pairs {
                let _: &mut form_urlencoded::Serializer<'_, String> = form.append_pair(name, value);
            }
            form.finish()
        };
        Ok(client
            .post(format!("{base}{path}"))
            .header(header::COOKIE, &self.cookie)
            .header(header::ORIGIN, base)
            .header("sec-fetch-site", "same-origin")
            .header("x-csrf-token", &self.csrf)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(body)
            .send()
            .await?)
    }
}
