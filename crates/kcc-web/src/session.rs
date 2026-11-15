//! In-memory Web UI sessions and their transport-bound cookies.

extern crate alloc;

use alloc::{
    collections::BTreeMap,
    sync::{Arc, Weak},
};
use core::{fmt, time::Duration};
use std::collections::HashMap;

use axum::http::{HeaderMap, HeaderValue, header, header::InvalidHeaderValue};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use kcc_app::{
    accounts::{
        AccountError, Clock,
        standing::{AccountStanding, PasswordFingerprint},
    },
    permissions::Role,
};
use kcc_i18n::locale::Locale;
use rand::{TryRng as _, rngs::SysRng};
use tokio::{
    sync::{RwLock, RwLockReadGuard},
    task::spawn_blocking,
    time::{Instant, MissedTickBehavior, interval},
};

use self::account::{SignedIn, StandingsError};

pub mod account;

/// Bytes of entropy in a session id and a CSRF token.
const TOKEN_BYTES: usize = 32;
/// Minimum interval between expiry sweeps.
const MIN_SWEEP_INTERVAL: Duration = Duration::from_secs(1);

/// A random, unguessable server-side session key.
#[derive(Clone, PartialEq, Eq, Hash)]
#[expect(
    clippy::module_name_repetitions,
    reason = "unambiguous security-domain name"
)]
pub struct SessionId(String);

impl SessionId {
    /// Generates a 256-bit id with the operating system RNG and base64url encoding.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::Random`] when the operating system RNG fails.
    fn generate() -> Result<Self, SessionError> {
        random_token().map(Self)
    }

    /// The cookie-safe base64url representation.
    #[inline]
    #[must_use]
    pub const fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for SessionId {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionId([REDACTED])")
    }
}

/// One authenticated or pre-authentication browser session.
#[derive(Clone)]
#[non_exhaustive]
pub struct Session {
    /// Signed-in username; absent until login succeeds.
    username: Option<String>,
    /// Resolved role; absent until login succeeds.
    role: Option<Role>,
    /// Locale used for authenticated pages.
    locale: Locale,
    /// Creation time in Unix seconds.
    created_at: u64,
    /// Last authenticated use in Unix seconds.
    last_seen: u64,
    /// Per-session CSRF token.
    csrf_token: String,
    /// Whether the account must choose a new password before using anything else.
    password_change: bool,
    /// Fingerprint of the password the session signed in with or last set.
    fingerprint: Option<PasswordFingerprint>,
}

impl fmt::Debug for Session {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            username,
            role,
            locale,
            created_at,
            last_seen,
            csrf_token: _,
            password_change,
            fingerprint,
        } = self;
        f.debug_struct("Session")
            .field("username", username)
            .field("role", role)
            .field("locale", locale)
            .field("created_at", created_at)
            .field("last_seen", last_seen)
            .field("csrf_token", &"[REDACTED]")
            .field("password_change", password_change)
            .field("fingerprint", fingerprint)
            .finish()
    }
}

impl Session {
    /// Signed-in username.
    #[inline]
    #[must_use]
    pub(crate) fn username(&self) -> Option<&str> {
        self.username.as_deref()
    }

    /// Resolved role.
    #[inline]
    #[must_use]
    pub(crate) const fn role(&self) -> Option<&Role> {
        self.role.as_ref()
    }

    /// Account locale.
    #[inline]
    #[must_use]
    pub(crate) const fn locale(&self) -> Locale {
        self.locale
    }

    /// The CSRF token rendered into authenticated forms and the page meta tag.
    #[inline]
    #[must_use]
    pub const fn csrf_token(&self) -> &str {
        self.csrf_token.as_str()
    }

    /// Whether this session has completed login.
    #[inline]
    #[must_use]
    pub const fn is_authenticated(&self) -> bool {
        self.username.is_some() && self.role.is_some()
    }

    /// Whether the account must choose a new password before anything else.
    #[inline]
    #[must_use]
    pub(crate) const fn password_change_required(&self) -> bool {
        self.password_change
    }

    /// Whether `standings` still back this session: its account exists, is enabled,
    /// holds the session's role and has the password the session knows. Sessions before
    /// login are always backed.
    fn backed_by(&self, standings: &BTreeMap<String, AccountStanding>) -> bool {
        let (Some(username), Some(role)) = (&self.username, &self.role) else {
            return true;
        };
        standings.get(username).is_some_and(|standing| {
            !standing.disabled
                && standing.role == role.name
                && self.fingerprint.is_some()
                && standing.fingerprint == self.fingerprint
        })
    }
}

/// How the running listener protects session cookies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CookieSecurity {
    /// The browser reaches the listener over TLS.
    Tls,
    /// Plain HTTP is permitted because the listener is loopback-only.
    LoopbackHttp,
}

impl CookieSecurity {
    /// Cookie name selected from the actual listener transport.
    #[inline]
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Tls => "__Host-kcc_session",
            Self::LoopbackHttp => "kcc_session",
        }
    }

    /// Builds the `Set-Cookie` value for a live session.
    #[inline]
    #[must_use]
    pub fn set_cookie(self, id: &SessionId) -> String {
        let secure = match self {
            Self::Tls => "; Secure",
            Self::LoopbackHttp => "",
        };
        format!(
            "{}={}; Path=/; HttpOnly; SameSite=Strict{secure}",
            self.name(),
            id.as_str()
        )
    }

    /// Builds the `Set-Cookie` value that deletes the browser cookie.
    #[inline]
    #[must_use]
    pub fn clear_cookie(self) -> String {
        let secure = match self {
            Self::Tls => "; Secure",
            Self::LoopbackHttp => "",
        };
        format!(
            "{}=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict{secure}",
            self.name()
        )
    }
}

/// Session creation or randomness errors.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
#[expect(
    clippy::module_name_repetitions,
    reason = "unambiguous security-domain name"
)]
pub enum SessionError {
    /// The operating system random source failed.
    #[error("operating system randomness is unavailable")]
    Random,
}

/// Shared session table and timeout policy.
#[derive(Clone)]
#[non_exhaustive]
#[expect(
    clippy::module_name_repetitions,
    reason = "unambiguous security-domain name"
)]
pub struct SessionStore {
    /// Shared table and timeout policy.
    inner: Arc<Inner>,
}

impl fmt::Debug for SessionStore {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionStore").finish_non_exhaustive()
    }
}

/// State shared by request handlers and the expiry sweeper.
struct Inner {
    /// Session records keyed by random id.
    sessions: RwLock<HashMap<SessionId, Session>>,
    /// Maximum inactivity period.
    idle_timeout: Duration,
    /// Maximum lifetime since login.
    absolute_timeout: Duration,
    /// Locale used before login.
    default_locale: Locale,
    /// Injectable Unix clock.
    clock: Arc<dyn Clock>,
    /// Shared by sign-ins and own password changes while they read an account and record
    /// it in a session; exclusive while sessions are checked against the accounts.
    account_reads: RwLock<()>,
}

impl SessionStore {
    /// Creates an empty in-memory store. A process restart deliberately drops every session.
    #[inline]
    #[must_use]
    pub(crate) fn new(
        idle_timeout: Duration,
        absolute_timeout: Duration,
        default_locale: Locale,
        clock: Arc<dyn Clock>,
    ) -> Self {
        let store = Self {
            inner: Arc::new(Inner {
                sessions: RwLock::new(HashMap::new()),
                idle_timeout,
                absolute_timeout,
                default_locale,
                clock,
                account_reads: RwLock::new(()),
            }),
        };
        store.spawn_sweeper();
        store
    }

    /// Creates a pre-authentication session for the login form.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::Random`] if id or CSRF token generation fails.
    pub(crate) async fn create_anonymous(&self) -> Result<(SessionId, Session), SessionError> {
        self.insert(None, self.inner.default_locale).await
    }

    /// Rotates an existing id into an authenticated session, preventing fixation.
    ///
    /// If `old_id` is absent or expired, login still creates a fresh authenticated session.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::Random`] if id or CSRF token generation fails.
    pub(crate) async fn login(
        &self,
        old_id: Option<&SessionId>,
        account: SignedIn,
        locale: Locale,
    ) -> Result<(SessionId, Session), SessionError> {
        if let Some(id) = old_id {
            drop(self.inner.sessions.write().await.remove(id));
        }
        self.insert(Some(account), locale).await
    }

    /// Holds off [`Self::end_stale`] while the caller reads an account and records it in
    /// a session, so no session is checked against an account read older than its own.
    // cancel-safe: waits for a lock only.
    pub(crate) async fn reading_account(&self) -> RwLockReadGuard<'_, ()> {
        self.inner.account_reads.read().await
    }

    /// Records the password `fingerprint` the session `id` now knows, after its own
    /// password change.
    pub(crate) async fn set_fingerprint(&self, id: &SessionId, fingerprint: PasswordFingerprint) {
        if let Some(session) = self.inner.sessions.write().await.get_mut(id) {
            session.fingerprint = Some(fingerprint);
        }
    }

    /// Reads the accounts with `read` and ends every signed-in session they no longer
    /// back: the account is gone or disabled, holds another role, or has another
    /// password than the session knows. Returns the accounts read and the number of
    /// sessions ended.
    ///
    /// # Errors
    ///
    /// [`StandingsError`] when `read` fails; no session ends then.
    // cancel-safe: sessions end only after the read completed, in one step.
    pub(crate) async fn end_stale<F>(
        &self,
        read: F,
    ) -> Result<(BTreeMap<String, AccountStanding>, usize), StandingsError>
    where
        F: FnOnce() -> Result<BTreeMap<String, AccountStanding>, AccountError> + Send + 'static,
    {
        let _exclusive = self.inner.account_reads.write().await;
        let standings = spawn_blocking(read).await??;
        let mut sessions = self.inner.sessions.write().await;
        let before = sessions.len();
        sessions.retain(|_id, session| session.backed_by(&standings));
        let ended = before.saturating_sub(sessions.len());
        drop(sessions);
        Ok((standings, ended))
    }

    /// Returns a live session and refreshes its idle deadline.
    pub(crate) async fn get(&self, id: &SessionId) -> Option<Session> {
        let now = self.inner.clock.unix_seconds();
        let mut sessions = self.inner.sessions.write().await;
        let expired = sessions
            .get(id)
            .is_none_or(|session| self.inner.expired(session, now));
        if expired {
            return sessions.remove(id).and(None);
        }
        let result = {
            let session = sessions.get_mut(id)?;
            session.last_seen = now;
            session.clone()
        };
        drop(sessions);
        Some(result)
    }

    /// Returns a live session without extending its idle deadline.
    pub(crate) async fn peek(&self, id: &SessionId) -> Option<Session> {
        let now = self.inner.clock.unix_seconds();
        let mut sessions = self.inner.sessions.write().await;
        match sessions.get(id) {
            Some(session) if !self.inner.expired(session, now) => Some(session.clone()),
            Some(_) => sessions.remove(id).and(None),
            None => None,
        }
    }

    /// Invalidates one session, including logout of an already-expired id.
    pub(crate) async fn invalidate(&self, id: &SessionId) {
        drop(self.inner.sessions.write().await.remove(id));
    }

    /// Ends every other session owned by `username` after a password change.
    pub(crate) async fn invalidate_other_user_sessions(&self, username: &str, keep: &SessionId) {
        self.inner
            .sessions
            .write()
            .await
            .retain(|id, session| id == keep || session.username.as_deref() != Some(username));
    }

    /// Rotates the current id after a privilege change and ends the user's other sessions.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::Random`] if replacement token generation fails.
    pub(crate) async fn rotate_privilege(
        &self,
        id: &SessionId,
        role: Role,
    ) -> Result<Option<(SessionId, Session)>, SessionError> {
        let Some(current) = self.peek(id).await else {
            return Ok(None);
        };
        let Some(username) = current.username else {
            return Ok(None);
        };
        let locale = current.locale;
        self.invalidate(id).await;
        let account = SignedIn::new(username.clone(), role, current.fingerprint);
        let replacement = self.insert(Some(account), locale).await?;
        self.invalidate_other_user_sessions(&username, &replacement.0)
            .await;
        Ok(Some(replacement))
    }

    /// Limits a fresh login to the password-change page until the password changes.
    pub(crate) async fn require_password_change(&self, id: &SessionId) {
        if let Some(session) = self.inner.sessions.write().await.get_mut(id) {
            session.password_change = true;
        }
    }

    /// Gives every live session of `username` the account's new `locale`, so its next page
    /// renders in it; other accounts' sessions keep theirs.
    pub(crate) async fn set_user_locale(&self, username: &str, locale: Locale) {
        self.inner
            .sessions
            .write()
            .await
            .values_mut()
            .filter(|session| session.username.as_deref() == Some(username))
            .for_each(|session| session.locale = locale);
    }

    /// Ends every session of `username`, after an administrator changed the account.
    pub(crate) async fn invalidate_user(&self, username: &str) {
        self.inner
            .sessions
            .write()
            .await
            .retain(|_id, session| session.username.as_deref() != Some(username));
    }

    /// The number of signed-in sessions that have not expired.
    pub(crate) async fn active(&self) -> usize {
        let now = self.inner.clock.unix_seconds();
        self.inner
            .sessions
            .read()
            .await
            .values()
            .filter(|session| session.is_authenticated() && !self.inner.expired(session, now))
            .count()
    }

    /// Ends every session holding the role `name`, after an administrator changed it.
    pub(crate) async fn invalidate_role(&self, name: &str) {
        self.inner
            .sessions
            .write()
            .await
            .retain(|_id, session| session.role.as_ref().is_none_or(|role| role.name != name));
    }

    /// Parses this listener's session cookie from request headers.
    #[must_use]
    pub(crate) fn id_from_headers(
        headers: &HeaderMap,
        security: CookieSecurity,
    ) -> Option<SessionId> {
        cookie(headers, security.name()).map(|value| SessionId(value.to_owned()))
    }

    /// A valid `Set-Cookie` header value for `id`.
    ///
    /// # Errors
    ///
    /// Returns an HTTP header error only if the cookie contract is accidentally made invalid.
    pub(crate) fn cookie_header(
        security: CookieSecurity,
        id: &SessionId,
    ) -> Result<HeaderValue, InvalidHeaderValue> {
        HeaderValue::from_str(&security.set_cookie(id))
    }

    /// Inserts a fresh session with independently generated id and CSRF token.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::Random`] when the operating system RNG fails.
    async fn insert(
        &self,
        account: Option<SignedIn>,
        locale: Locale,
    ) -> Result<(SessionId, Session), SessionError> {
        let id = SessionId::generate()?;
        let now = self.inner.clock.unix_seconds();
        let (username, role, fingerprint) = match account.map(SignedIn::into_parts) {
            Some((username, role, fingerprint)) => (Some(username), Some(role), fingerprint),
            None => (None, None, None),
        };
        let session = Session {
            username,
            role,
            locale,
            created_at: now,
            last_seen: now,
            csrf_token: random_token()?,
            password_change: false,
            fingerprint,
        };
        drop(
            self.inner
                .sessions
                .write()
                .await
                .insert(id.clone(), session.clone()),
        );
        Ok((id, session))
    }

    /// Starts a periodic expiry pass that exits after the final store handle is dropped.
    fn spawn_sweeper(&self) {
        let weak = Arc::downgrade(&self.inner);
        let shortest = self.inner.idle_timeout.min(self.inner.absolute_timeout);
        let interval = shortest.div_f64(2.0).max(MIN_SWEEP_INTERVAL);
        drop(tokio::spawn(sweep_task(weak, interval)));
    }
}

impl Inner {
    /// Whether idle or absolute lifetime is exhausted at `now`.
    const fn expired(&self, session: &Session, now: u64) -> bool {
        now.saturating_sub(session.last_seen) >= self.idle_timeout.as_secs()
            || now.saturating_sub(session.created_at) >= self.absolute_timeout.as_secs()
    }
}

/// Removes expired sessions until the store no longer exists.
async fn sweep_task(inner: Weak<Inner>, period: Duration) {
    let mut timer = interval(period);
    timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let _: Instant = timer.tick().await;
    loop {
        let _: Instant = timer.tick().await;
        let Some(strong) = inner.upgrade() else {
            return;
        };
        let now = strong.clock.unix_seconds();
        strong
            .sessions
            .write()
            .await
            .retain(|_id, session| !strong.expired(session, now));
    }
}

/// Generates a 256-bit base64url token with no padding.
///
/// # Errors
///
/// Returns [`SessionError::Random`] when the operating system RNG fails.
fn random_token() -> Result<String, SessionError> {
    let mut bytes = [0_u8; TOKEN_BYTES];
    SysRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_error| SessionError::Random)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

/// The first cookie value named `name` across every Cookie header.
fn cookie<'headers>(headers: &'headers HeaderMap, name: &str) -> Option<&'headers str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find_map(|(key, value)| (key == name).then_some(value))
}

#[cfg(test)]
#[path = "session_tests.rs"]
mod tests;
