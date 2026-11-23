//! A native OAuth client of kcc's authorization server as an MCP client runs it: PKCE,
//! registration, the authorization request, the browser's sign-in and consent, and the
//! token endpoint.
#![expect(
    clippy::missing_errors_doc,
    reason = "test support returns the boxed error of whatever step failed"
)]

use core::sync::atomic::{AtomicU64, Ordering};
use std::{
    process,
    time::{SystemTime, UNIX_EPOCH},
};

use reqwest::{Response, StatusCode, header};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use url::{Url, form_urlencoded};

use crate::{
    browser::{Browser, hx_redirect},
    fixture::{Fixture, PASSWORD, Server, TestResult},
    tokens::{Tokens, redeem, tokens_of},
};

/// The loopback redirect URI every test client registers.
pub(crate) const REDIRECT: &str = "http://127.0.0.1:9/callback";

/// Makes every generated value of one test process distinct.
static COUNTER: AtomicU64 = AtomicU64::new(0);

/// A value unique within this test process: 64 lowercase hex characters.
pub(crate) fn unique(label: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos());
    let count = COUNTER.fetch_add(1, Ordering::SeqCst);
    Sha256::digest(format!("{label}:{nanos}:{count}:{}", process::id()))
        .iter()
        .flat_map(|byte| [byte >> 4_u8, byte & 15])
        .filter_map(|nibble| char::from_digit(u32::from(nibble), 16))
        .collect()
}

/// `bytes` as unpadded base64url.
pub(crate) fn base64url(bytes: &[u8]) -> TestResult<String> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut text = String::new();
    for chunk in bytes.chunks(3) {
        let mut word = [0_u8; 4];
        for (slot, byte) in word.iter_mut().skip(1).zip(chunk) {
            *slot = *byte;
        }
        let bits = u32::from_be_bytes(word);
        for index in 0..=u32::try_from(chunk.len())? {
            let shift = 18_u32
                .checked_sub(index.checked_mul(6).ok_or("overflow")?)
                .ok_or("overflow")?;
            let sextet = usize::try_from((bits >> shift) & 63)?;
            text.push(char::from(*ALPHABET.get(sextet).ok_or("sextet")?));
        }
    }
    Ok(text)
}

/// A PKCE verifier and its S256 challenge.
#[expect(
    clippy::field_scoped_visibility_modifiers,
    reason = "the tests read and adjust the flow's values"
)]
pub(crate) struct Pkce {
    /// The verifier (64 characters).
    pub(crate) verifier: String,
    /// `base64url(SHA-256(verifier))`.
    pub(crate) challenge: String,
}

impl Pkce {
    /// A fresh pair.
    pub(crate) fn new() -> TestResult<Self> {
        let verifier = unique("verifier");
        let challenge = base64url(&Sha256::digest(verifier.as_bytes()))?;
        Ok(Self {
            verifier,
            challenge,
        })
    }
}

/// A request that reached the consent step: its client, PKCE pair, state and id.
#[expect(
    clippy::field_scoped_visibility_modifiers,
    reason = "the tests read and adjust the flow's values"
)]
pub(crate) struct Consent {
    /// The registered client.
    pub(crate) client: String,
    /// The PKCE pair.
    pub(crate) pkce: Pkce,
    /// The `state` sent.
    pub(crate) state: String,
    /// The pending request's id, from the redirect to the consent page.
    pub(crate) id: String,
}

/// The query parameters of `location` (absolute or relative).
pub(crate) fn query(location: &str) -> TestResult<Vec<(String, String)>> {
    let url = Url::parse(location).or_else(|_relative| Url::parse("http://x/")?.join(location))?;
    Ok(url.query_pairs().into_owned().collect())
}

/// The value of `name` among `pairs`.
pub(crate) fn param<'pairs>(pairs: &'pairs [(String, String)], name: &str) -> Option<&'pairs str> {
    pairs
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.as_str())
}

/// `response`'s `Location`.
pub(crate) fn location(response: &Response) -> Option<String> {
    response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

/// Registers a client named `name` with `redirect_uris`; the status and the JSON answer.
pub(crate) async fn register(
    fixture: &Fixture,
    server: &Server,
    (name, redirect_uris): (&str, &[&str]),
) -> TestResult<(StatusCode, Value)> {
    let answer = fixture
        .http()
        .post(format!("{}/oauth/register", server.base()))
        .json(&json!({
            "client_name": name,
            "redirect_uris": redirect_uris,
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
        }))
        .send()
        .await?;
    let status = answer.status();
    Ok((status, answer.json().await.unwrap_or(Value::Null)))
}

/// A client registered with [`REDIRECT`]; its id.
pub(crate) async fn client(fixture: &Fixture, server: &Server) -> TestResult<String> {
    let (status, body) = register(fixture, server, ("Test client", &[REDIRECT])).await?;
    if status != StatusCode::CREATED {
        return Err(format!("registration answered {status}: {body}").into());
    }
    Ok(body
        .get("client_id")
        .and_then(Value::as_str)
        .ok_or("no client_id")?
        .to_owned())
}

/// `GET /oauth/authorize` with `pairs`.
pub(crate) async fn authorize(
    fixture: &Fixture,
    server: &Server,
    pairs: &[(&str, &str)],
) -> TestResult<Response> {
    let mut url = Url::parse(&format!("{}/oauth/authorize", server.base()))?;
    let _: &mut form_urlencoded::Serializer<'_, url::UrlQuery<'_>> =
        url.query_pairs_mut().extend_pairs(pairs);
    Ok(fixture.http().get(url).send().await?)
}

/// A valid authorization request of `client` for the server's resource, answered with
/// the redirect to the consent page.
pub(crate) async fn begin(fixture: &Fixture, server: &Server, client: &str) -> TestResult<Consent> {
    let pkce = Pkce::new()?;
    let state = unique("state");
    let resource = server.resource();
    let answer = authorize(
        fixture,
        server,
        &[
            ("response_type", "code"),
            ("client_id", client),
            ("redirect_uri", REDIRECT),
            ("code_challenge", &pkce.challenge),
            ("code_challenge_method", "S256"),
            ("state", &state),
            ("resource", &resource),
            ("scope", "mcp"),
        ],
    )
    .await?;
    let to = location(&answer).ok_or_else(|| format!("authorize answered {}", answer.status()))?;
    let id = to
        .strip_prefix("/ui/oauth/consent?request=")
        .ok_or_else(|| format!("authorize went to {to}"))?
        .to_owned();
    Ok(Consent {
        client: client.to_owned(),
        pkce,
        state,
        id,
    })
}

/// `pairs` form-encoded.
pub(crate) fn form(pairs: &[(&str, &str)]) -> String {
    let mut form = form_urlencoded::Serializer::new(String::new());
    for (name, value) in pairs {
        let _: &mut form_urlencoded::Serializer<'_, String> = form.append_pair(name, value);
    }
    form.finish()
}

/// `account` signs in and approves `consent`; the code from the `HX-Redirect`.
pub(crate) async fn approve(
    fixture: &Fixture,
    server: &Server,
    consent: &Consent,
    account: &str,
) -> TestResult<String> {
    let browser = Browser::resume(fixture, server, (account, PASSWORD), &consent.id).await?;
    let answer = browser.decide(fixture, &consent.id, "approve").await?;
    let target = hx_redirect(&answer)
        .ok_or_else(|| format!("approve answered {} without HX-Redirect", answer.status()))?;
    let pairs = query(&target)?;
    Ok(param(&pairs, "code").ok_or("no code")?.to_owned())
}

/// The whole flow for `account` with a new client; its tokens.
pub(crate) async fn connect(
    fixture: &Fixture,
    server: &Server,
    account: &str,
) -> TestResult<Tokens> {
    let client = client(fixture, server).await?;
    let consent = begin(fixture, server, &client).await?;
    let code = approve(fixture, server, &consent, account).await?;
    tokens_of(redeem(fixture, server, &consent, &code).await?, &client).await
}
