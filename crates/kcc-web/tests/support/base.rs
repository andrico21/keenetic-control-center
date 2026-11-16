//! The Web UI without routers: its state, accounts, audit log and clock.

extern crate alloc;

use alloc::sync::Arc;
use core::{
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use kcc_app::{
    accounts::{AccountStore, Clock, NewAccount},
    audit::AuditLog,
    permissions::Role,
    persist::StateStore,
    secrets::MasterKey,
};
use kcc_i18n::locale::Locale;
use kcc_web::{WebState, WebStateConfig, session::CookieSecurity};
use secrecy::SecretString;
use tempfile::TempDir;

use super::outcome::TestResult;

/// The only browser origin the Web UI accepts.
pub(crate) const ORIGIN: &str = "http://127.0.0.1:8080";

/// Password of every fixture account.
pub(crate) const PASSWORD: &str = "correct horse battery staple";

/// An account: its name, its role and, when it has one, its locale.
pub(crate) type Account<'name> = (&'name str, &'name str, Option<&'name str>);

/// A clock that stays at one Unix second until a test moves it.
#[derive(Debug)]
pub(crate) struct Frozen(AtomicU64);

impl Frozen {
    /// A clock standing at the Unix second `now`.
    pub(crate) const fn at(now: u64) -> Self {
        Self(AtomicU64::new(now))
    }

    /// Moves the clock to the Unix second `now`.
    pub(crate) fn set(&self, now: u64) {
        self.0.store(now, Ordering::SeqCst);
    }
}

impl Clock for Frozen {
    fn unix_seconds(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// The state, accounts and audit log of a Web UI.
#[expect(
    clippy::field_scoped_visibility_modifiers,
    reason = "the suites without routers keep the parts they need"
)]
pub(crate) struct Core {
    /// Holds the state directory.
    pub(crate) directory: TempDir,
    /// The state store.
    pub(crate) state: StateStore,
    /// The account store.
    pub(crate) accounts: Arc<AccountStore>,
    /// The audit log.
    pub(crate) audit: AuditLog,
    /// The account and session clock.
    clock: Arc<dyn Clock>,
}

impl Core {
    /// A fresh state directory with `accounts`, all signing in with [`PASSWORD`].
    pub(crate) fn new(clock: Arc<dyn Clock>, accounts: &[Account<'_>]) -> TestResult<Self> {
        let directory = TempDir::new()?;
        let state = StateStore::open(&directory.path().join("state"))?;
        let store = Arc::new(AccountStore::new(
            state.clone(),
            MasterKey::generate()?,
            Duration::from_secs(60),
            Arc::clone(&clock),
        ));
        for (name, role, locale) in accounts {
            let account = NewAccount::new(
                (*name).to_owned(),
                SecretString::from(PASSWORD),
                (*role).to_owned(),
            );
            store.create(match locale {
                Some(tag) => account.with_locale((*tag).to_owned()),
                None => account,
            })?;
        }
        let audit = AuditLog::spawn(&state)?;
        Ok(Self {
            directory,
            state,
            accounts: store,
            audit,
            clock,
        })
    }

    /// The Web UI state with `roles`, `(idle, absolute)` session limits and `cookies`.
    pub(crate) fn web(
        &self,
        roles: Vec<Role>,
        (session_idle, session_absolute): (Duration, Duration),
        cookies: CookieSecurity,
    ) -> WebState {
        WebState::new(WebStateConfig {
            default_locale: Locale::En,
            accounts: Arc::clone(&self.accounts),
            audit: self.audit.clone(),
            roles,
            session_idle,
            session_absolute,
            allowed_origins: vec![ORIGIN.to_owned()],
            cookie_security: cookies,
            clock: Arc::clone(&self.clock),
        })
    }
}
