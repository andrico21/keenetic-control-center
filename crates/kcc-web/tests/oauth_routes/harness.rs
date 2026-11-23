//! kcc's authorization server in the Web UI router, without a listener: accounts `alice`
//! (admin) and `vera` (viewer), a client registered on the loopback, and a browser.
#![expect(
    clippy::missing_errors_doc,
    reason = "test support returns the boxed error of whatever step failed"
)]

extern crate alloc;

use alloc::{collections::BTreeSet, sync::Arc};
use core::time::Duration;

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
    response::Response,
};
use kcc_app::{
    accounts::{AccountStore, Clock},
    mcp_auth::clients::{ClientRegistration, ClientStore},
    permissions::built_in_roles,
    persist::StateStore,
    secrets::MasterKey,
    settings::Config,
};
use kcc_web::{
    oauth::{Activation, OAuthServer},
    session::CookieSecurity,
    web_router,
};
use sha2::{Digest as _, Sha256};
use tower::ServiceExt as _;
use url::{Url, UrlQuery, form_urlencoded::Serializer};

use crate::support::{
    base::{Core, Frozen, ORIGIN, PASSWORD},
    outcome::TestResult,
    page::{cookie_pair, form, header_text, meta_content, text},
};

/// The issuer of the default configuration's loopback listener.
pub(crate) const ISSUER: &str = "http://localhost:8443";

/// The resource the server accepts.
pub(crate) const RESOURCE: &str = "http://127.0.0.1:8443/mcp";

/// The redirect URI the test client registered.
pub(crate) const REDIRECT: &str = "http://127.0.0.1:9/callback";

/// A PKCE verifier (64 characters) and its S256 challenge.
pub(crate) fn pkce(seed: &str) -> (String, String) {
    let verifier = format!("{seed:-<64}");
    let digest = Sha256::digest(verifier.as_bytes());
    (verifier, base64url(&digest))
}

/// `bytes` as unpadded base64url.
fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut text = String::new();
    for chunk in bytes.chunks(3) {
        let mut word = [0_u8; 4];
        for (slot, byte) in word.iter_mut().skip(1).zip(chunk) {
            *slot = *byte;
        }
        let bits = u32::from_be_bytes(word);
        for index in 0..=chunk.len() {
            let shift =
                u32::try_from(18_usize.saturating_sub(index.saturating_mul(6))).unwrap_or(0);
            let sextet = usize::try_from((bits >> shift) & 63).unwrap_or(0);
            text.extend(ALPHABET.get(sextet).map(|symbol| char::from(*symbol)));
        }
    }
    text
}

/// The Web UI with an active authorization server.
#[expect(
    clippy::field_scoped_visibility_modifiers,
    reason = "the tests reach the server and the client directly"
)]
pub(crate) struct Harness {
    /// State, accounts and audit.
    core: Core,
    /// The Web UI.
    router: Router,
    /// The authorization server.
    pub(crate) server: Arc<OAuthServer>,
    /// The registered client.
    pub(crate) client: String,
}

/// A browser session: cookie and CSRF token.
#[expect(
    clippy::field_scoped_visibility_modifiers,
    reason = "the tests send the cookie themselves"
)]
pub(crate) struct Browser {
    /// `name=value` of the session cookie.
    pub(crate) cookie: String,
    /// The page's CSRF token.
    pub(crate) csrf: String,
}

impl Harness {
    /// The Web UI over a fresh state with the server active for [`RESOURCE`], and a client
    /// named `client_name`.
    pub(crate) fn new(client_name: &str) -> TestResult<Self> {
        let clock: Arc<dyn Clock> = Arc::new(Frozen::at(1_700_000_000));
        let core = Core::new(
            Arc::clone(&clock),
            &[("alice", "admin", None), ("vera", "viewer", None)],
            &built_in_roles(),
        )?;
        let config = Config::from_toml_str("[web]\nenabled = true\n")?;
        let server = Arc::new(
            OAuthServer::of(
                &config,
                (core.state.clone(), MasterKey::generate()?),
                Arc::clone(&clock),
            )
            .ok_or("no issuer")?,
        );
        server.activate(Some(Activation::new(
            BTreeSet::from([RESOURCE.to_owned()]),
            (Duration::from_mins(15), Duration::from_hours(24)),
        )));
        let client = ClientStore::new(core.state.clone(), clock)
            .register(&ClientRegistration::new(
                Some(client_name.to_owned()),
                vec![REDIRECT.to_owned()],
            ))?
            .id()
            .to_owned();
        let web = core
            .web(
                built_in_roles().to_vec(),
                (Duration::from_hours(1), Duration::from_hours(10)),
                CookieSecurity::LoopbackHttp,
            )
            .with_oauth(Some(Arc::clone(&server)));
        Ok(Self {
            router: web_router(web),
            core,
            server,
            client,
        })
    }

    /// The account store.
    pub(crate) fn accounts(&self) -> &AccountStore {
        &self.core.accounts
    }

    /// The state directory.
    pub(crate) const fn state(&self) -> &StateStore {
        &self.core.state
    }

    /// Sends `request` through the Web UI.
    pub(crate) async fn send(&self, request: Request<Body>) -> TestResult<Response> {
        Ok(self.router.clone().oneshot(request).await?)
    }

    /// `GET path`.
    pub(crate) async fn get(&self, path: &str, cookie: Option<&str>) -> TestResult<Response> {
        let mut request = Request::get(path);
        if let Some(value) = cookie {
            request = request.header(header::COOKIE, value);
        }
        self.send(request.body(Body::empty())?).await
    }

    /// A same-origin htmx `POST` of `pairs` to `path` as `browser`; without the CSRF token
    /// when `csrf` is false.
    pub(crate) async fn post(
        &self,
        path: &str,
        (browser, csrf): (&Browser, bool),
        pairs: &[(&str, &str)],
    ) -> TestResult<Response> {
        let mut request = Request::post(path)
            .header(header::COOKIE, &browser.cookie)
            .header(header::ORIGIN, ORIGIN)
            .header("sec-fetch-site", "same-origin")
            .header("hx-request", "true")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        if csrf {
            request = request.header("x-csrf-token", &browser.csrf);
        }
        self.send(request.body(Body::from(form(pairs)))?).await
    }

    /// A protocol `POST` of `pairs` to `path` (no session, no CSRF).
    pub(crate) async fn protocol(
        &self,
        path: &str,
        pairs: &[(&str, &str)],
    ) -> TestResult<Response> {
        self.send(
            Request::post(path)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form(pairs)))?,
        )
        .await
    }

    /// `GET /oauth/authorize` with `pairs`.
    pub(crate) async fn authorize(&self, pairs: &[(&str, &str)]) -> TestResult<Response> {
        let mut url = Url::parse("http://x/oauth/authorize")?;
        let _: &mut Serializer<'_, UrlQuery<'_>> = url.query_pairs_mut().extend_pairs(pairs);
        self.get(
            &format!("/oauth/authorize?{}", url.query().unwrap_or_default()),
            None,
        )
        .await
    }

    /// A valid request of the client with `challenge` and `state`; the pending id.
    pub(crate) async fn begin(&self, challenge: &str, state: &str) -> TestResult<String> {
        let answer = self
            .authorize(&[
                ("response_type", "code"),
                ("client_id", &self.client),
                ("redirect_uri", REDIRECT),
                ("code_challenge", challenge),
                ("code_challenge_method", "S256"),
                ("state", state),
                ("resource", RESOURCE),
            ])
            .await?;
        let to = header_text(&answer, "location").ok_or("no redirect to the consent page")?;
        Ok(to
            .strip_prefix("/ui/oauth/consent?request=")
            .ok_or_else(|| format!("redirected to {to}"))?
            .to_owned())
    }

    /// `name` signs in with the resume id `consent`; the browser and the login's
    /// `Location`.
    pub(crate) async fn sign_in(
        &self,
        name: &str,
        consent: &str,
    ) -> TestResult<(Browser, Option<String>)> {
        let page = self.get("/ui/login", None).await?;
        let anonymous_cookie = cookie_pair(&page)?;
        let anonymous_csrf =
            meta_content(&text(page).await?, "csrf-token").ok_or("no CSRF token")?;
        let anonymous = Browser {
            cookie: anonymous_cookie,
            csrf: anonymous_csrf,
        };
        let login = Request::post("/ui/login")
            .header(header::COOKIE, &anonymous.cookie)
            .header(header::ORIGIN, ORIGIN)
            .header("sec-fetch-site", "same-origin")
            .header("x-csrf-token", &anonymous.csrf)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(form(&[
                ("username", name),
                ("password", PASSWORD),
                ("consent", consent),
            ])))?;
        let signed = self.send(login).await?;
        if signed.status() != StatusCode::SEE_OTHER {
            return Err(format!("login answered {}", signed.status()).into());
        }
        let location = header_text(&signed, "location");
        let cookie = cookie_pair(&signed)?;
        let account = self.get("/ui/account", Some(&cookie)).await?;
        let csrf = meta_content(&text(account).await?, "csrf-token").ok_or("no CSRF token")?;
        Ok((Browser { cookie, csrf }, location))
    }

    /// The code of an approval of `id` by `name`.
    pub(crate) async fn approved_code(&self, name: &str, id: &str) -> TestResult<String> {
        let (browser, _) = self.sign_in(name, id).await?;
        let answer = self
            .post(
                "/ui/oauth/consent/approve",
                (&browser, true),
                &[("request", id)],
            )
            .await?;
        let target = header_text(&answer, "hx-redirect").ok_or("no HX-Redirect")?;
        Url::parse(&target)?
            .query_pairs()
            .find(|(key, _)| key == "code")
            .map(|(_, value)| value.into_owned())
            .ok_or_else(|| "no code".into())
    }
}
