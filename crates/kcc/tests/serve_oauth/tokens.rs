//! The token endpoint as an MCP client calls it: code redemption, refresh, revocation.
#![expect(
    clippy::missing_errors_doc,
    reason = "test support returns the boxed error of whatever step failed"
)]

use reqwest::{Response, StatusCode, header};
use serde_json::Value;

use crate::{
    fixture::{Fixture, Server, TestResult},
    flow::{Consent, REDIRECT, form},
};

/// The tokens of one completed flow.
#[expect(
    clippy::field_scoped_visibility_modifiers,
    reason = "the tests read and adjust the flow's values"
)]
pub(crate) struct Tokens {
    /// The registered client.
    pub(crate) client: String,
    /// The access token.
    pub(crate) access: String,
    /// The refresh token.
    pub(crate) refresh: String,
}

/// `POST /oauth/token` with `pairs`.
pub(crate) async fn token(
    fixture: &Fixture,
    server: &Server,
    pairs: &[(&str, &str)],
) -> TestResult<Response> {
    let body = form(pairs);
    Ok(fixture
        .http()
        .post(format!("{}/oauth/token", server.base()))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await?)
}

/// Redeems `code` of `consent` at the token endpoint; the answer.
pub(crate) async fn redeem(
    fixture: &Fixture,
    server: &Server,
    consent: &Consent,
    code: &str,
) -> TestResult<Response> {
    let resource = server.resource();
    token(
        fixture,
        server,
        &[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", REDIRECT),
            ("client_id", &consent.client),
            ("code_verifier", &consent.pkce.verifier),
            ("resource", &resource),
        ],
    )
    .await
}

/// Refreshes with `refresh` of `client`; the answer.
pub(crate) async fn refresh(
    fixture: &Fixture,
    server: &Server,
    (client, refresh): (&str, &str),
) -> TestResult<Response> {
    token(
        fixture,
        server,
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh),
            ("client_id", client),
        ],
    )
    .await
}

/// Revokes `token` of `client` (RFC 7009); the answer.
pub(crate) async fn revoke(
    fixture: &Fixture,
    server: &Server,
    (client, token): (&str, &str),
) -> TestResult<Response> {
    Ok(fixture
        .http()
        .post(format!("{}/oauth/revoke", server.base()))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(form(&[("token", token), ("client_id", client)]))
        .send()
        .await?)
}

/// The `error` of a refused token answer.
pub(crate) async fn error_of(answer: Response) -> TestResult<(StatusCode, String)> {
    let status = answer.status();
    let body: Value = answer.json().await?;
    Ok((
        status,
        body.get("error")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
    ))
}

/// The access and refresh token of a successful token answer.
pub(crate) async fn tokens_of(answer: Response, client: &str) -> TestResult<Tokens> {
    let status = answer.status();
    let body: Value = answer.json().await?;
    if status != StatusCode::OK {
        return Err(format!("token answered {status}: {body}").into());
    }
    let text = |name: &str| -> TestResult<String> {
        Ok(body
            .get(name)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("no {name}"))?
            .to_owned())
    };
    Ok(Tokens {
        client: client.to_owned(),
        access: text("access_token")?,
        refresh: text("refresh_token")?,
    })
}
