//! Reactive HTTP session management for authenticated router requests.

pub(crate) mod journal;
#[cfg(test)]
mod refresh_tests;
pub(crate) mod send;
mod transport;

use alloc::sync::Arc;
use core::{
    fmt,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
use std::{
    sync::{Mutex as StdMutex, MutexGuard, PoisonError},
    time::Instant,
};

use reqwest::{
    Client, Method, Response, StatusCode,
    header::{self, HeaderMap, HeaderValue},
    multipart::Form,
    redirect::Policy,
};
use secrecy::{ExposeSecret as _, SecretString};
use serde::Serialize;
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use self::{journal::Journal, transport::install_ring_provider};
use crate::{
    AuthError, LocalCause, RciError, RouterUrl, TransportCause,
    auth::{Credentials, Scheme, WwwAuthenticate, ndw2_response},
    auth_digest,
    auth_ndw4::{Cache, Exchange},
    auth_options::{ARGON2_ITERATIONS, ARGON2_MEMORY_KIB, Mode, Options},
    auth_token, diag,
    ndw4_reply::Caps,
    observe::{LoginScheme, RciObserver},
};

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
        cookie_header(&self.cookie_name, &self.cookie_value)
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
    /// Explicit permission to enter passwordless factory setup.
    bootstrap_enabled: bool,
    /// Whether an unauthenticated probe confirmed factory setup.
    bootstrap_active: AtomicBool,
    /// One key set bound to this manager's immutable router and credentials.
    ndw4_cache: Arc<Cache>,
    /// Per-router digest nonce state.
    digest: auth_digest::State,
    /// Current session, read synchronously so requests never hold the login lock on wire I/O.
    session: StdMutex<Option<Session>>,
    /// Serializes only authentication exchanges.
    login: Mutex<()>,
    /// Optional login observer (self-metrics).
    observer: Option<Arc<dyn RciObserver>>,
    /// Log identity and collapsed warnings, shared with the client that owns this manager.
    journal: Arc<Journal>,
}

impl Manager {
    /// Probes authentication through this session's transport and bound origin.
    ///
    /// # Errors
    /// Returns policy, transport or timeout failures.
    // cancel-safe: the unauthenticated GET changes no local session state.
    pub(crate) async fn probe_auth(&self, router: &RouterUrl) -> Result<Response, RciError> {
        transport::probe_auth(self, router).await
    }

    /// Enables factory setup after an unauthenticated `/auth` returns HTTP 200.
    /// Replace this manager after setting the first password.
    #[inline]
    #[must_use]
    pub const fn with_bootstrap(mut self) -> Self {
        self.bootstrap_enabled = true;
        self
    }

    /// Reports whether the router confirmed passwordless setup.
    #[inline]
    #[must_use]
    pub fn is_bootstrap(&self) -> bool {
        self.bootstrap_active.load(Ordering::Acquire)
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
            .no_proxy()
            .redirect(Policy::none())
            .connect_timeout(timeouts.connect)
            .read_timeout(timeouts.read)
            .build()
            .map_err(|_error| {
                RciError::Transport(TransportCause::Local(LocalCause::ClientBuild))
            })?;
        Ok(Self {
            client,
            router,
            credentials,
            options: Options::default(),
            password_configured: true,
            bootstrap_enabled: false,
            bootstrap_active: AtomicBool::new(false),
            ndw4_cache: Arc::new(Cache::default()),
            digest: auth_digest::State::default(),
            session: StdMutex::new(None),
            login: Mutex::new(()),
            observer: None,
            journal: Arc::new(Journal::default()),
        })
    }

    /// Creates a manager with explicit authentication policy and a policy-checked HTTP builder.
    ///
    /// # Errors
    /// Returns validation errors for an invalid Argon2 cap or a profile without credentials.
    #[doc(hidden)]
    #[inline]
    pub fn with_options_and_client_builder(
        router: RouterUrl,
        credentials: Option<Credentials>,
        options: Options,
        builder: reqwest::ClientBuilder,
    ) -> Result<Self, RciError> {
        let password_configured = credentials.is_some();
        let identity = credentials
            .unwrap_or_else(|| Credentials::new(String::new(), SecretString::from(String::new())));
        Self::with_client_builder(router, identity, HttpTimeouts::default(), builder)?
            .with_auth(options, password_configured)
    }

    /// Replaces the authentication policy; `password_configured` says whether the manager's
    /// credentials are real password credentials rather than token-only placeholders.
    ///
    /// # Errors
    /// Returns validation errors for an invalid Argon2 cap or a policy without credentials.
    pub(crate) fn with_auth(
        mut self,
        options: Options,
        password_configured: bool,
    ) -> Result<Self, RciError> {
        if !ARGON2_MEMORY_KIB.contains(&options.max_argon2_memory_kib)
            || !ARGON2_ITERATIONS.contains(&options.max_argon2_iterations)
            || (!password_configured && options.experimental_token.is_none())
        {
            return Err(RciError::Validation);
        }
        self.options = options;
        self.password_configured = password_configured;
        Ok(self)
    }

    /// Reports every login exchange of this manager to `observer`.
    #[inline]
    #[must_use]
    pub fn with_observer(mut self, observer: Option<Arc<dyn RciObserver>>) -> Self {
        self.observer = observer;
        self
    }

    /// Sets the router profile id (never its display name) this manager's log lines carry.
    #[inline]
    #[must_use]
    pub fn with_log_id(mut self, log_id: String) -> Self {
        self.journal = Arc::new(Journal::new(log_id));
        self
    }

    /// The router profile id this manager's log lines carry; empty when unset.
    #[inline]
    #[must_use]
    pub fn log_id(&self) -> &str {
        self.journal.id()
    }

    /// Shares the log identity and collapsed warnings of the client that owns this manager.
    #[must_use]
    pub(crate) fn with_journal(mut self, journal: Arc<Journal>) -> Self {
        self.journal = journal;
        self
    }

    /// The log identity and collapsed warnings of this manager.
    pub(crate) fn journal(&self) -> &Journal {
        &self.journal
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
        if self.usable_session().is_some() || self.is_bootstrap() {
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
        let label = self.journal.label(&method, path);
        if let Some(token) = &self.options.experimental_token {
            let mut request = self.client.request(method.clone(), self.url(path));
            if let Some(value) = body {
                request = request.json(value);
            }
            let response = auth_token::send(request, token, &label).await?;
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
            return self
                .digest
                .request(request, &self.credentials, &label)
                .await;
        }
        self.ensure_password_session().await?;
        if self.is_bootstrap() {
            let mut request = self.client.request(method, self.url(path));
            if let Some(value) = body {
                request = request.json(value);
            }
            return send::send(request, &label).await;
        }
        let first_session = self
            .usable_session()
            .ok_or(RciError::Auth(AuthError::Rejected))?;
        let first = self
            .send_with_session(method.clone(), path, body, &first_session)
            .await?;
        self.refresh_session(&first_session, first.status(), first.headers());
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
        self.refresh_session(&retry_session, retry.status(), retry.headers());
        Ok(retry)
    }

    /// Sends a retryable authenticated GET.
    ///
    /// # Errors
    ///
    /// Returns authentication or transport failures.
    // NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned
    // router session. Apart from that, GET has no router-side mutation, and a cancelled
    // re-authentication is recovered by the next request.
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
        let request = self
            .client
            .post(self.url(path))
            .header(header::COOKIE, session.header_value()?)
            .multipart(form);
        send::send(request, &self.journal.label(&Method::POST, path)).await
    }

    /// The key cache of this manager, shared with sessions of the same router and credentials.
    pub(crate) fn key_cache(&self) -> Arc<Cache> {
        Arc::clone(&self.ndw4_cache)
    }

    /// Replaces the key cache with one shared by managers of the same router and credentials.
    #[must_use]
    pub(crate) fn with_key_cache(mut self, cache: Arc<Cache>) -> Self {
        self.ndw4_cache = cache;
        self
    }

    /// Whether a router session cookie is held.
    pub(crate) fn has_session(&self) -> bool {
        lock(&self.session).is_some()
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
            let request = self
                .client
                .delete(self.url("/auth"))
                .header(header::COOKIE, cookie);
            drop(send::send(request, &self.journal.label(&Method::DELETE, "/auth")).await);
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
        let started = Instant::now();
        let result = self.exchange().await;
        self.journal.signed_in(&result, started.elapsed());
        if let Some(observer) = &self.observer {
            observer.authentication(result.as_ref().ok().copied(), result.is_ok());
        }
        result.map(drop)
    }

    /// Runs the challenge-response exchange and names the scheme that succeeded.
    ///
    /// # Errors
    ///
    /// Returns typed authentication, transport, or HTTP status failures.
    // NOT cancel-safe: see `authenticate`.
    async fn exchange(&self) -> Result<LoginScheme, RciError> {
        let challenge_response = send::send(
            self.client.get(self.url("/auth")),
            &self.journal.label(&Method::GET, "/auth"),
        )
        .await?;
        if challenge_response.status().is_success() {
            if self.bootstrap_enabled && challenge_response.status() == StatusCode::OK {
                self.bootstrap_active.store(true, Ordering::Release);
                return Ok(LoginScheme::Existing);
            }
            if let Some(current) = self.session() {
                self.refresh_session(
                    &current,
                    challenge_response.status(),
                    challenge_response.headers(),
                );
            }
            if self.usable_session().is_some() {
                return Ok(LoginScheme::Existing);
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
                let session = self
                    .ndw4_exchange()
                    .authenticate(challenge, &challenge_response)
                    .await?;
                *lock(&self.session) = Some(session);
                return Ok(LoginScheme::Ndw4);
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
            .map_err(|_error| RciError::Transport(TransportCause::Local(LocalCause::Serialize)))?,
        );
        let request = self
            .client
            .post(self.url("/auth"))
            .header(header::COOKIE, pending.header_value()?)
            .header(header::CONTENT_TYPE, "application/json")
            .body(body.to_string());
        let login_response =
            send::send(request, &self.journal.label(&Method::POST, "/auth")).await?;
        if login_response.status() == StatusCode::UNAUTHORIZED {
            return Err(RciError::Auth(AuthError::Rejected));
        }
        if !login_response.status().is_success() {
            return Err(RciError::Http {
                status: login_response.status().as_u16(),
            });
        }
        *lock(&self.session) = Some(pending.into());
        Ok(LoginScheme::Ndw2)
    }

    /// The ndw4 exchange bound to this manager's transport, identity, Argon2 caps and keys.
    fn ndw4_exchange(&self) -> Exchange<'_> {
        Exchange {
            client: &self.client,
            origin: self.router.as_str(),
            credentials: &self.credentials,
            caps: Caps {
                memory_kib: self.options.max_argon2_memory_kib,
                iterations: self.options.max_argon2_iterations,
            },
            cache: &self.ndw4_cache,
            journal: &self.journal,
        }
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
        let label = self.journal.label(&method, path);
        let mut request = self
            .client
            .request(method, self.url(path))
            .header(header::COOKIE, session.header_value()?);
        if let Some(value) = body {
            request = request.json(value);
        }
        send::send(request, &label).await
    }

    /// Returns a non-expired session snapshot.
    fn usable_session(&self) -> Option<Session> {
        lock(&self.session)
            .as_ref()
            .filter(|session| !session.is_expired())
            .cloned()
    }

    /// Applies a sliding cookie refresh from the answer to a request sent with `sent`.
    ///
    /// A 401 never refreshes, and an answer refreshes only while the current cookie is still
    /// the one the request carried, so a late answer cannot replace a newer login. A malformed
    /// refresh keeps the current cookie: the answer was already applied by the router, and a
    /// dead cookie is replaced at its next 401.
    fn refresh_session(&self, sent: &Session, status: StatusCode, headers: &HeaderMap) {
        if status == StatusCode::UNAUTHORIZED {
            return;
        }
        let mut current = lock(&self.session);
        if let Some(session) = current.as_mut()
            && session.same_cookie(sent)
            && let Ok(Some(parsed)) = parse_set_cookie(headers, Some(&session.cookie_name))
        {
            session.cookie_value = parsed.cookie_value;
            session.expires_at = parsed.expires_at;
        }
    }

    /// Joins one absolute path to the validated router origin.
    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.router.as_str().trim_end_matches('/'))
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
        cookie_header(&self.cookie_name, &self.cookie_value)
    }
}

/// The private `Cookie` request header for one cookie.
///
/// # Errors
///
/// Returns [`RciError::Transport`] if the cookie cannot be represented as a header.
fn cookie_header(name: &str, value: &SecretString) -> Result<HeaderValue, RciError> {
    HeaderValue::from_str(&format!("{name}={}", value.expose_secret()))
        .map_err(|_error| RciError::Transport(TransportCause::Local(LocalCause::Header)))
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

/// Parses the matching `Set-Cookie` header and its `Max-Age`.
///
/// A cookie with another name is skipped before its value is read, so an unrelated cookie
/// that is not visible ASCII is absent rather than an error; without an expected name such
/// a header is skipped too.
///
/// # Errors
///
/// Returns an error when a matching cookie is malformed or not a valid header value.
pub(crate) fn parse_set_cookie(
    headers: &HeaderMap,
    expected_name: Option<&str>,
) -> Result<Option<ParsedCookie>, RciError> {
    for raw in headers.get_all(header::SET_COOKIE) {
        let raw_name = raw
            .as_bytes()
            .split(|byte| matches!(byte, b'=' | b';'))
            .next()
            .map(<[u8]>::trim_ascii);
        if expected_name.is_some_and(|expected| raw_name != Some(expected.as_bytes())) {
            continue;
        }
        let Ok(text) = raw.to_str() else {
            if expected_name.is_some() {
                return Err(RciError::Transport(TransportCause::Local(
                    LocalCause::Header,
                )));
            }
            continue;
        };
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
pub(crate) fn map_reqwest_error(error: &reqwest::Error) -> RciError {
    if error.is_timeout() {
        RciError::Timeout
    } else {
        RciError::Transport(diag::classify(error))
    }
}

/// Locks short-lived synchronous state and recovers after a poisoned holder.
pub(crate) fn lock<T>(mutex: &StdMutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
