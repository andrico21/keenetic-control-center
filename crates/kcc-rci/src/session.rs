//! Reactive HTTP session management for authenticated router requests.

use alloc::sync::Arc;
use core::{fmt, time::Duration};
use std::{
    sync::{Mutex as StdMutex, MutexGuard, OnceLock, PoisonError},
    time::Instant,
};

use reqwest::{
    Client, Method, Response, StatusCode,
    header::{self, HeaderMap, HeaderValue},
    multipart::Form,
    redirect::Policy,
};
use rustls::crypto::{CryptoProvider, ring::default_provider};
use secrecy::{ExposeSecret as _, SecretString};
use serde::Serialize;
use tokio::{sync::Mutex, task::JoinHandle, time};
use zeroize::Zeroizing;

use crate::{
    AuthError, RciError, RouterUrl,
    auth::{Credentials, Scheme, WwwAuthenticate, ndw2_response},
    auth_digest,
    auth_ndw4::{Cache, Exchange},
    auth_options::{Mode, Options},
    auth_token,
};

/// Default interval for keeping a session active while long-lived work needs it.
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(120);

/// Configurable HTTP connection and response-read timeouts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct HttpTimeouts {
    /// Maximum time spent establishing a connection.
    pub connect: Duration,
    /// Maximum idle gap while reading a response.
    pub read: Duration,
}

impl Default for HttpTimeouts {
    #[inline]
    fn default() -> Self {
        Self {
            connect: Duration::from_secs(5),
            read: Duration::from_secs(30),
        }
    }
}

/// Retry classification for an authenticated request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RequestKind {
    /// A GET or an RCI `show`, `show rc`, or `show sc` operation.
    Idempotent,
    /// A POST for which a router 401 proves middleware rejected it before body processing.
    PostRejectedBeforeBody,
    /// A request whose effects cannot safely be retried.
    NonRetryable,
}

impl RequestKind {
    /// Whether a 401 permits one transparent replay.
    const fn retry_on_unauthorized(self) -> bool {
        matches!(self, Self::Idempotent | Self::PostRejectedBeforeBody)
    }
}

/// An authenticated router session using the router-selected cookie name.
#[derive(Clone)]
#[non_exhaustive]
pub struct Session {
    /// Cookie name chosen by the router.
    cookie_name: String,
    /// Cookie value, which is an authentication secret.
    cookie_value: SecretString,
    /// Local expiry derived from `Max-Age`.
    expires_at: Option<Instant>,
}

impl Session {
    /// Returns the router-selected cookie name.
    #[inline]
    #[must_use]
    pub fn cookie_name(&self) -> &str {
        &self.cookie_name
    }

    /// Whether the cookie's declared local expiry has passed.
    #[inline]
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.expires_at
            .is_some_and(|expiry| Instant::now() >= expiry)
    }

    /// Produces the private wire cookie header.
    ///
    /// # Errors
    ///
    /// Returns [`RciError::Transport`] if the cookie cannot be represented as a header.
    pub(crate) fn header_value(&self) -> Result<HeaderValue, RciError> {
        HeaderValue::from_str(&format!(
            "{}={}",
            self.cookie_name,
            self.cookie_value.expose_secret()
        ))
        .map_err(|_error| RciError::Transport)
    }

    /// Replaces expiry and value when a response refreshes this cookie.
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed matching cookie.
    pub(crate) fn refresh_from_headers(&mut self, headers: &HeaderMap) -> Result<(), RciError> {
        let Some(parsed) = parse_set_cookie(headers, Some(&self.cookie_name))? else {
            return Ok(());
        };
        self.cookie_value = parsed.cookie_value;
        self.expires_at = parsed.expires_at;
        Ok(())
    }

    /// Whether this session identifies the same issued cookie as another snapshot.
    fn same_cookie(&self, other: &Self) -> bool {
        self.cookie_name == other.cookie_name
            && self.cookie_value.expose_secret() == other.cookie_value.expose_secret()
    }
}

impl fmt::Debug for Session {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            cookie_name,
            cookie_value: _,
            expires_at,
        } = self;
        f.debug_struct("Session")
            .field("cookie_name", cookie_name)
            .field("cookie_value", &"[REDACTED]")
            .field("expires_at", expires_at)
            .finish()
    }
}

/// Owns router credentials, the current cookie, and single-flight login state.
#[derive(Debug)]
#[non_exhaustive]
pub struct Manager {
    /// HTTP client with redirects disabled.
    client: Client,
    /// Router origin.
    router: RouterUrl,
    /// Authentication credentials.
    credentials: Credentials,
    /// Explicit authentication policy.
    options: Options,
    /// Whether password credentials were supplied (token-only managers have none).
    password_configured: bool,
    /// One key set bound to this manager's immutable router and credentials.
    ndw4_cache: Cache,
    /// Per-router digest nonce state.
    digest: auth_digest::State,
    /// Current session, read synchronously so requests never hold the login lock on wire I/O.
    session: StdMutex<Option<Session>>,
    /// Serializes only authentication exchanges.
    login: Mutex<()>,
}

/// Public protocol name for the single-flight router session manager.
#[expect(
    clippy::module_name_repetitions,
    reason = "the protocol API is explicitly named SessionManager"
)]
pub type SessionManager = Manager;

impl Manager {
    /// Creates a session manager with explicit timeout settings.
    ///
    /// # Errors
    ///
    /// Returns [`RciError::Transport`] when the TLS provider or HTTP client cannot be built.
    #[inline]
    pub fn new(
        router: RouterUrl,
        credentials: Credentials,
        timeouts: HttpTimeouts,
    ) -> Result<Self, RciError> {
        install_ring_provider()?;
        Self::with_client_builder(router, credentials, timeouts, Client::builder())
    }

    /// Creates a manager from an HTTP builder for deterministic transport integration.
    ///
    /// # Errors
    ///
    /// Returns [`RciError::Transport`] when the TLS provider or HTTP client cannot be built.
    #[doc(hidden)]
    #[inline]
    pub fn with_client_builder(
        router: RouterUrl,
        credentials: Credentials,
        timeouts: HttpTimeouts,
        builder: reqwest::ClientBuilder,
    ) -> Result<Self, RciError> {
        install_ring_provider()?;
        let client = builder
            .redirect(Policy::none())
            .connect_timeout(timeouts.connect)
            .read_timeout(timeouts.read)
            .build()
            .map_err(|_error| RciError::Transport)?;
        Ok(Self {
            client,
            router,
            credentials,
            options: Options::default(),
            password_configured: true,
            ndw4_cache: Cache::default(),
            digest: auth_digest::State::default(),
            session: StdMutex::new(None),
            login: Mutex::new(()),
        })
    }

    /// Creates a manager with 5 s connect and 30 s read timeouts.
    ///
    /// # Errors
    ///
    /// Returns [`RciError::Transport`] when the TLS provider or HTTP client cannot be built.
    #[inline]
    pub fn with_defaults(router: RouterUrl, credentials: Credentials) -> Result<Self, RciError> {
        Self::new(router, credentials, HttpTimeouts::default())
    }

    /// Creates a manager with explicit protocol policy and optional password credentials.
    ///
    /// # Errors
    /// Returns validation errors for an invalid memory cap or a profile without credentials.
    #[inline]
    pub fn with_options(
        router: RouterUrl,
        credentials: Option<Credentials>,
        options: Options,
    ) -> Result<Self, RciError> {
        if !(8..=0x0004_0000).contains(&options.max_argon2_memory_kib)
            || (credentials.is_none() && options.experimental_token.is_none())
        {
            return Err(RciError::Validation);
        }
        let password_configured = credentials.is_some();
        let identity = credentials
            .unwrap_or_else(|| Credentials::new(String::new(), SecretString::from(String::new())));
        let mut manager = Self::with_defaults(router, identity)?;
        manager.options = options;
        manager.password_configured = password_configured;
        Ok(manager)
    }

    /// Returns a snapshot of the current in-memory session.
    #[inline]
    #[must_use]
    pub fn session(&self) -> Option<Session> {
        lock(&self.session).clone()
    }

    /// Ensures a locally usable session, authenticating through `/auth` when needed.
    ///
    /// # Errors
    ///
    /// Returns a transport, HTTP, unsupported-authentication, or rejection error.
    // NOT cancel-safe: cancellation during POST /auth can leave a valid router session that
    // was not installed locally; the next call safely starts a fresh authentication exchange.
    #[inline]
    pub async fn ensure_session(&self) -> Result<(), RciError> {
        if self.options.experimental_token.is_some() || self.options.mode == Mode::DigestProxy {
            return Ok(());
        }
        self.ensure_password_session().await
    }

    /// Ensures a cookie after explicit password policy selection.
    ///
    /// # Errors
    /// Returns authentication or transport failures.
    // NOT cancel-safe: an interrupted handshake can leave remote state without a local cookie.
    async fn ensure_password_session(&self) -> Result<(), RciError> {
        if self.usable_session().is_some() {
            return Ok(());
        }
        let _login_guard = self.login.lock().await;
        if self.usable_session().is_some() {
            return Ok(());
        }
        self.authenticate().await
    }

    /// Sends an authenticated request and transparently replays it at most once after 401.
    ///
    /// # Errors
    ///
    /// Returns authentication or transport failures. A final HTTP response, including a second
    /// 401, is returned to the caller for normal status mapping.
    // NOT cancel-safe: a POST may have reached the router when this future is cancelled; callers
    // must use `PostRejectedBeforeBody` only for the router's pre-body 401 contract.
    #[inline]
    pub async fn request<T>(
        &self,
        method: Method,
        path: &str,
        body: Option<&T>,
        kind: RequestKind,
    ) -> Result<Response, RciError>
    where
        T: Serialize + Sync + ?Sized,
    {
        if let Some(token) = &self.options.experimental_token {
            let mut request = self.client.request(method.clone(), self.url(path));
            if let Some(value) = body {
                request = request.json(value);
            }
            let response = auth_token::send(request, token).await?;
            if response.status() != StatusCode::UNAUTHORIZED
                || !self.options.token_fallback
                || !self.password_configured
                || !kind.retry_on_unauthorized()
            {
                return auth_token::accepted(response);
            }
        }
        if self.options.mode == Mode::DigestProxy {
            let mut request = self.client.request(method, self.url(path));
            if let Some(value) = body {
                request = request.json(value);
            }
            return self.digest.request(request, &self.credentials).await;
        }
        self.ensure_password_session().await?;
        let first_session = self
            .usable_session()
            .ok_or(RciError::Auth(AuthError::Rejected))?;
        let first = self
            .send_with_session(method.clone(), path, body, &first_session)
            .await?;
        self.refresh_session(first.headers())?;
        if first.status() != StatusCode::UNAUTHORIZED || !kind.retry_on_unauthorized() {
            return Ok(first);
        }

        self.reauthenticate_after(&first_session).await?;
        let retry_session = self
            .usable_session()
            .ok_or(RciError::Auth(AuthError::Rejected))?;
        let retry = self
            .send_with_session(method, path, body, &retry_session)
            .await?;
        self.refresh_session(retry.headers())?;
        Ok(retry)
    }

    /// Sends a retryable authenticated GET.
    ///
    /// # Errors
    ///
    /// Returns authentication or transport failures.
    // cancel-safe: GET has no router-side mutation, and a cancelled re-authentication is recovered
    // by the next request.
    #[inline]
    pub async fn get(&self, path: &str) -> Result<Response, RciError> {
        self.request::<()>(Method::GET, path, None, RequestKind::Idempotent)
            .await
    }

    /// Sends a POST whose 401 is guaranteed to occur before router body processing.
    ///
    /// # Errors
    ///
    /// Returns authentication or transport failures.
    // NOT cancel-safe: cancellation after transmission may leave a completed router mutation.
    #[inline]
    pub async fn post<T>(&self, path: &str, body: &T) -> Result<Response, RciError>
    where
        T: Serialize + Sync + ?Sized,
    {
        self.request(
            Method::POST,
            path,
            Some(body),
            RequestKind::PostRejectedBeforeBody,
        )
        .await
    }

    /// Sends an authenticated multipart POST without transport replay.
    ///
    /// # Errors
    ///
    /// Returns authentication or transport failures.
    // NOT cancel-safe: cancellation after transmission may leave a completed upload.
    #[inline]
    pub async fn post_multipart(&self, path: &str, form: Form) -> Result<Response, RciError> {
        self.ensure_password_session().await?;
        let session = self
            .usable_session()
            .ok_or(RciError::Auth(AuthError::Rejected))?;
        self.client
            .post(self.url(path))
            .header(header::COOKIE, session.header_value()?)
            .multipart(form)
            .send()
            .await
            .map_err(|error| map_reqwest_error(&error))
    }

    /// Deletes the router session and always clears the local cookie.
    // NOT cancel-safe: cancellation after DELETE can leave uncertainty about router logout, while
    // the local session is cleared before the wire operation.
    #[inline]
    pub async fn logout(&self) {
        let removed = lock(&self.session).take();
        if let Some(session) = removed
            && let Ok(cookie) = session.header_value()
        {
            drop(
                self.client
                    .delete(self.url("/auth"))
                    .header(header::COOKIE, cookie)
                    .send()
                    .await,
            );
        }
    }

    /// Starts a 120-second `/auth` keepalive until the returned guard is dropped.
    #[inline]
    pub fn start_keepalive(self: &Arc<Self>) -> Keepalive {
        let manager = Arc::clone(self);
        let task = tokio::spawn(async move {
            let mut interval = time::interval(KEEPALIVE_INTERVAL);
            interval.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
            let _: time::Instant = interval.tick().await;
            loop {
                let _: time::Instant = interval.tick().await;
                drop(manager.keepalive_once().await);
            }
        });
        Keepalive { task }
    }

    /// Sends one keepalive probe and reacts to an expired router session.
    ///
    /// # Errors
    ///
    /// Returns authentication, transport, or non-success HTTP status errors.
    // cancel-safe: GET /auth is read-only, and cancellation leaves local state unchanged.
    async fn keepalive_once(&self) -> Result<(), RciError> {
        if self.options.experimental_token.is_some() || self.options.mode == Mode::DigestProxy {
            return Ok(());
        }
        let response = self.get("/auth").await?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(RciError::Http {
                status: response.status().as_u16(),
            })
        }
    }

    /// Performs one complete challenge-response exchange.
    ///
    /// # Errors
    ///
    /// Returns typed authentication, transport, or HTTP status failures.
    // NOT cancel-safe: cancellation after POST /auth can authenticate remotely without installing
    // the local cookie; a later exchange replaces it.
    async fn authenticate(&self) -> Result<(), RciError> {
        let challenge_response = self
            .client
            .get(self.url("/auth"))
            .send()
            .await
            .map_err(|error| map_reqwest_error(&error))?;
        if challenge_response.status().is_success() {
            self.refresh_session(challenge_response.headers())?;
            if self.usable_session().is_some() {
                return Ok(());
            }
        }
        if challenge_response.status() != StatusCode::UNAUTHORIZED {
            return Err(RciError::Http {
                status: challenge_response.status().as_u16(),
            });
        }
        let headers = challenge_response
            .headers()
            .get_all(header::WWW_AUTHENTICATE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .collect::<Vec<_>>()
            .join(", ");
        let authenticate = WwwAuthenticate::parse(&headers)
            .ok()
            .ok_or(RciError::Auth(AuthError::Unsupported))?;
        if self.options.mode != Mode::Ndw2 {
            if let Some(challenge) = authenticate
                .schemes()
                .iter()
                .find_map(|scheme| match scheme {
                    Scheme::Ndw4(challenge) => Some(challenge),
                    Scheme::Ndw2(_) | Scheme::Unknown(_) => None,
                })
            {
                let exchange = Exchange {
                    client: &self.client,
                    origin: self.router.as_str(),
                    credentials: &self.credentials,
                    memory_cap: self.options.max_argon2_memory_kib,
                    cache: &self.ndw4_cache,
                };
                let session = exchange
                    .authenticate(challenge, &challenge_response)
                    .await?;
                *lock(&self.session) = Some(session);
                return Ok(());
            }
            if self.options.mode == Mode::Ndw4 || authenticate.schemes().iter().any(|scheme| matches!(scheme, Scheme::Unknown(unknown) if unknown.name.eq_ignore_ascii_case("x-ndw4-interactive"))) {
                return Err(RciError::Auth(AuthError::Unsupported));
            }
        }
        let challenge = authenticate
            .ndw2()
            .ok_or(RciError::Auth(AuthError::Unsupported))?;
        let pending = parse_set_cookie(
            challenge_response.headers(),
            Some(&challenge.session_cookie),
        )?
        .ok_or(RciError::Auth(AuthError::Rejected))?;
        if pending.cookie_value.expose_secret() != challenge.session_id {
            return Err(RciError::Auth(AuthError::Rejected));
        }

        let response_hash =
            ndw2_response(&self.credentials, &challenge.realm, &challenge.challenge);
        let body = Zeroizing::new(
            serde_json::to_string(&LoginBody {
                login: &self.credentials.login,
                password: &response_hash,
            })
            .map_err(|_error| RciError::Transport)?,
        );
        let login_response = self
            .client
            .post(self.url("/auth"))
            .header(header::COOKIE, pending.header_value()?)
            .header(header::CONTENT_TYPE, "application/json")
            .body(body.to_string())
            .send()
            .await
            .map_err(|error| map_reqwest_error(&error))?;
        if login_response.status() == StatusCode::UNAUTHORIZED {
            return Err(RciError::Auth(AuthError::Rejected));
        }
        if !login_response.status().is_success() {
            return Err(RciError::Http {
                status: login_response.status().as_u16(),
            });
        }
        *lock(&self.session) = Some(pending.into());
        Ok(())
    }

    /// Re-authenticates only if no concurrent request has already replaced the failed cookie.
    ///
    /// # Errors
    ///
    /// Returns an error if replacement authentication fails.
    // NOT cancel-safe: cancellation can interrupt the replacement authentication exchange.
    async fn reauthenticate_after(&self, failed: &Session) -> Result<(), RciError> {
        let _login_guard = self.login.lock().await;
        if self
            .usable_session()
            .is_some_and(|current| !current.same_cookie(failed))
        {
            return Ok(());
        }
        *lock(&self.session) = None;
        self.authenticate().await
    }

    /// Sends one request using a snapshot, without holding any manager lock across wire I/O.
    ///
    /// # Errors
    ///
    /// Returns an error if the cookie is invalid or the request fails on the wire.
    // NOT cancel-safe: POST cancellation may occur after the router processes the body.
    async fn send_with_session<T>(
        &self,
        method: Method,
        path: &str,
        body: Option<&T>,
        session: &Session,
    ) -> Result<Response, RciError>
    where
        T: Serialize + Sync + ?Sized,
    {
        let mut request = self
            .client
            .request(method, self.url(path))
            .header(header::COOKIE, session.header_value()?);
        if let Some(value) = body {
            request = request.json(value);
        }
        request
            .send()
            .await
            .map_err(|error| map_reqwest_error(&error))
    }

    /// Returns a non-expired session snapshot.
    fn usable_session(&self) -> Option<Session> {
        lock(&self.session)
            .as_ref()
            .filter(|session| !session.is_expired())
            .cloned()
    }

    /// Applies a sliding cookie refresh from response headers.
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed matching cookie.
    fn refresh_session(&self, headers: &HeaderMap) -> Result<(), RciError> {
        if let Some(session) = lock(&self.session).as_mut() {
            session.refresh_from_headers(headers)?;
        }
        Ok(())
    }

    /// Joins one absolute path to the validated router origin.
    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.router.as_str().trim_end_matches('/'))
    }
}

/// A running keepalive task that stops when dropped.
#[derive(Debug)]
#[must_use = "dropping the guard stops session keepalive"]
pub struct Keepalive {
    /// Background keepalive task.
    task: JoinHandle<()>,
}

impl Drop for Keepalive {
    #[inline]
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Borrowed ndw2 login payload.
#[derive(Serialize)]
struct LoginBody<'value> {
    /// Account login.
    login: &'value str,
    /// Zeroizing response digest.
    password: &'value str,
}

/// Parsed cookie fields before installation.
pub(crate) struct ParsedCookie {
    /// Router-selected cookie name.
    cookie_name: String,
    /// Secret cookie value.
    cookie_value: SecretString,
    /// Expiry derived from `Max-Age`.
    expires_at: Option<Instant>,
}

impl ParsedCookie {
    /// Creates a private cookie request header.
    ///
    /// # Errors
    ///
    /// Returns [`RciError::Transport`] if the cookie cannot be represented as a header.
    fn header_value(&self) -> Result<HeaderValue, RciError> {
        HeaderValue::from_str(&format!(
            "{}={}",
            self.cookie_name,
            self.cookie_value.expose_secret()
        ))
        .map_err(|_error| RciError::Transport)
    }
}

impl From<ParsedCookie> for Session {
    #[inline]
    fn from(cookie: ParsedCookie) -> Self {
        let ParsedCookie {
            cookie_name,
            cookie_value,
            expires_at,
        } = cookie;
        Self {
            cookie_name,
            cookie_value,
            expires_at,
        }
    }
}

/// Installs rustls ring once, accepting a provider installed by another crate.
///
/// # Errors
///
/// Returns [`RciError::Transport`] when no process-wide provider can be installed or found.
fn install_ring_provider() -> Result<(), RciError> {
    static INSTALL: OnceLock<Result<(), ()>> = OnceLock::new();
    INSTALL
        .get_or_init(|| {
            default_provider()
                .install_default()
                .map_err(|_provider| ())
                .or_else(|()| {
                    CryptoProvider::get_default()
                        .is_some()
                        .then_some(())
                        .ok_or(())
                })
        })
        .map_err(|()| RciError::Transport)
}

/// Parses the matching `Set-Cookie` header and its `Max-Age`.
///
/// # Errors
///
/// Returns an error when a matching cookie is malformed or not a valid header value.
pub(crate) fn parse_set_cookie(
    headers: &HeaderMap,
    expected_name: Option<&str>,
) -> Result<Option<ParsedCookie>, RciError> {
    for raw in headers.get_all(header::SET_COOKIE) {
        let text = raw.to_str().map_err(|_error| RciError::Transport)?;
        let mut parts = text.split(';').map(str::trim);
        let Some((name, value)) = parts.next().and_then(|pair| pair.split_once('=')) else {
            continue;
        };
        if expected_name.is_some_and(|expected| expected != name) {
            continue;
        }
        if name.is_empty() || value.is_empty() {
            return Err(RciError::Auth(AuthError::Rejected));
        }
        let max_age = parts.find_map(|attribute| {
            let (key, attribute_value) = attribute.split_once('=')?;
            key.eq_ignore_ascii_case("max-age")
                .then(|| attribute_value.parse::<u64>().ok())
                .flatten()
        });
        let expires_at =
            max_age.and_then(|seconds| Instant::now().checked_add(Duration::from_secs(seconds)));
        return Ok(Some(ParsedCookie {
            cookie_name: name.to_owned(),
            cookie_value: SecretString::from(value.to_owned()),
            expires_at,
        }));
    }
    Ok(None)
}

/// Maps reqwest timeouts separately from other transport failures.
fn map_reqwest_error(error: &reqwest::Error) -> RciError {
    if error.is_timeout() {
        RciError::Timeout
    } else {
        RciError::Transport
    }
}

/// Locks short-lived synchronous state and recovers after a poisoned holder.
fn lock<T>(mutex: &StdMutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
