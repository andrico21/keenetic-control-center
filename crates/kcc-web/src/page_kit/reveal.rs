//! Reveal: the separate, audited action that shows one stored secret.
//!
//! It needs `RevealSecrets` on the router and is audited whether allowed or not, with the
//! secret's name and never its value. The value appears only in the dialog the action
//! answers with, in a read-only field with Copy; closing the dialog empties it, so the
//! value leaves the page.

use core::fmt;

use askama::Template;
use axum::response::Response;
use fluent_bundle::FluentArgs;
use kcc_app::permissions::Permission;
use kcc_i18n::{bundle::tr, keys};
use secrecy::{ExposeSecret, SecretString};

use super::{audit::Record, context::fragment_shell, gate::allowed, outcome::Failure};
use crate::{
    WebState,
    authz::CurrentUser,
    errors::{self, Kind},
    page::{Localize, Shell},
};

/// The dialog of one Reveal: the secret with Copy, or why it could not be read.
#[derive(Template)]
#[template(path = "partials/kit_reveal.html")]
struct RevealDialog {
    /// Locale carrier.
    shell: Shell,
    /// "Stored value: <name>".
    title: String,
    /// The secret; only this dialog's markup reads it.
    secret: Option<SecretString>,
    /// Why the secret could not be read.
    problem: Option<String>,
}

impl fmt::Debug for RevealDialog {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RevealDialog")
            .field("title", &self.title)
            .field("problem", &self.problem)
            .finish_non_exhaustive()
    }
}

impl Localize for RevealDialog {
    fn shell(&self) -> &Shell {
        &self.shell
    }
}

impl RevealDialog {
    /// The secret, for the dialog's read-only field.
    fn value(&self) -> Option<&str> {
        self.secret.as_ref().map(ExposeSecret::expose_secret)
    }
}

/// A user asking to see one stored secret of a router.
pub(crate) struct Reveal<'call> {
    /// Web services.
    state: &'call WebState,
    /// The signed-in user.
    user: &'call CurrentUser,
    /// Router profile id.
    router: &'call str,
}

impl<'call> Reveal<'call> {
    /// `user` asks to see a secret of `router`.
    pub(crate) const fn new(
        state: &'call WebState,
        user: &'call CurrentUser,
        router: &'call str,
    ) -> Self {
        Self {
            state,
            user,
            router,
        }
    }

    /// Checks `RevealSecrets`, reads the secret called `name` with `read` and answers with
    /// the dialog showing it; refused, the localized 403. The audit log records the action
    /// `web.secret_reveal` on `name` and how it ended, never the value.
    // NOT cancel-safe: an abandoned append may still be written.
    pub(crate) async fn show<F>(self, name: &str, read: F) -> Response
    where
        F: Future<Output = Result<SecretString, Failure>>,
    {
        let locale = self.user.locale();
        let record = Record::on_router("web.secret_reveal", self.router, name.to_owned());
        if !allowed(self.user, self.router, &[Permission::RevealSecrets]) {
            record.append(self.state, self.user, "forbidden").await;
            return errors::response(Kind::Forbidden, fragment_shell(locale));
        }
        let mut args = FluentArgs::new();
        args.set("name", name.to_owned());
        let mut dialog = RevealDialog {
            shell: fragment_shell(locale),
            title: tr(locale, keys::WEB_KIT_REVEAL_TITLE, Some(&args)),
            secret: None,
            problem: None,
        };
        let outcome = match read.await {
            Ok(secret) => {
                dialog.secret = Some(secret);
                "success"
            }
            Err(failure) => {
                dialog.problem = Some(failure.message().to_owned());
                failure.audit()
            }
        };
        record.append(self.state, self.user, outcome).await;
        errors::render(&dialog)
    }
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use alloc::sync::Arc;
    use core::{error::Error, time::Duration};

    use axum::{body::to_bytes, http::StatusCode};
    use kcc_app::{
        accounts::{AccountStore, Clock},
        audit::{AuditLog, verify_chain},
        permissions::built_in_roles,
        persist::StateStore,
        secrets::MasterKey,
    };
    use kcc_i18n::locale::Locale;
    use secrecy::SecretString;
    use tempfile::TempDir;

    use super::{Reveal, RevealDialog};
    use crate::{
        WebState, WebStateConfig, authz::CurrentUser, page_kit::context::fragment_shell,
        session::CookieSecurity,
    };

    /// A frozen clock.
    #[derive(Debug)]
    struct Frozen;

    impl Clock for Frozen {
        fn unix_seconds(&self) -> u64 {
            1_700_000_000
        }
    }

    #[tokio::test]
    async fn only_reveal_secrets_shows_a_secret_and_the_audit_never_holds_it()
    -> Result<(), Box<dyn Error>> {
        let directory = TempDir::new()?;
        let state_dir = directory.path().join("state");
        let store = StateStore::open(&state_dir)?;
        let clock: Arc<dyn Clock> = Arc::new(Frozen);
        let accounts = AccountStore::new(
            store.clone(),
            MasterKey::generate()?,
            Duration::from_secs(60),
            Arc::clone(&clock),
        );
        let web = WebState::new(WebStateConfig {
            default_locale: Locale::En,
            accounts: Arc::new(accounts),
            audit: AuditLog::spawn(&store)?,
            roles: Vec::from(built_in_roles()),
            session_idle: Duration::from_secs(60),
            session_absolute: Duration::from_secs(600),
            allowed_origins: Vec::new(),
            cookie_security: CookieSecurity::LoopbackHttp,
            clock,
        });
        let [_, operator, admin] = built_in_roles();
        let secret = "hunter22-psk";
        let read = async || Ok(SecretString::from(secret));
        let operating = CurrentUser::signed_in("olga".to_owned(), operator, Locale::En);
        let refused = Reveal::new(&web, &operating, "home")
            .show("ssid-1", read())
            .await;
        assert_eq!(
            refused.status(),
            StatusCode::FORBIDDEN,
            "RevealSecrets needed"
        );
        let refused_page = to_bytes(refused.into_body(), 0x0001_0000).await?;
        assert!(
            !String::from_utf8(refused_page.to_vec())?.contains(secret),
            "a refusal shows nothing"
        );
        let administering = CurrentUser::signed_in("ada".to_owned(), admin, Locale::En);
        let shown = Reveal::new(&web, &administering, "home")
            .show("ssid-1", read())
            .await;
        assert_eq!(shown.status(), StatusCode::OK, "revealed");
        let html = String::from_utf8(to_bytes(shown.into_body(), 0x0001_0000).await?.to_vec())?;
        assert!(
            html.contains(&format!("value=\"{secret}\" readonly")),
            "only the dialog's read-only field holds it: {html}"
        );
        let entries = verify_chain(&state_dir)?;
        let outcomes: Vec<(&str, &str, Option<&str>)> = entries
            .iter()
            .map(|entry| {
                (
                    entry.action.as_str(),
                    entry.outcome.as_str(),
                    entry.target.as_deref(),
                )
            })
            .collect();
        assert_eq!(
            outcomes,
            [
                ("web.secret_reveal", "forbidden", Some("ssid-1")),
                ("web.secret_reveal", "success", Some("ssid-1"))
            ],
            "audited either way"
        );
        assert!(
            !serde_json::to_string(&entries)?.contains(secret),
            "never the value"
        );
        let dialog = RevealDialog {
            shell: fragment_shell(Locale::En),
            title: "ssid-1".to_owned(),
            secret: Some(SecretString::from(secret)),
            problem: None,
        };
        assert!(!format!("{dialog:?}").contains(secret), "Debug redacts");
        Ok(())
    }
}
