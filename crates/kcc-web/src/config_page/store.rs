//! The backups of one router as the page reaches them: the store's file work off the async
//! runtime, and an action on them opened for one user and audited once.

use alloc::sync::Arc;

use axum::{
    http::StatusCode,
    response::{IntoResponse as _, Response},
};
use kcc_app::{
    backups::{BackupError, BackupInfo},
    permissions::Permission,
};
use secrecy::SecretString;
use serde_json::Value;
use tokio::task::spawn_blocking;

use crate::{
    WebState,
    authz::CurrentUser,
    errors::{self, Kind},
    fleet::BackupServices,
    page_kit::{
        audit::Record,
        context::{self, fragment_shell},
        gate::allowed,
        respond::Answer,
    },
};

/// Longest reason the page gives a backup: the store takes 48 characters.
pub(crate) const REASON_ROOM: usize = 48;

/// Why the store could not do what the page asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StoreError {
    /// No such backup.
    Missing,
    /// The store failed; the cause is logged.
    Failed,
}

impl StoreError {
    /// The store error of `error`, logged unless it is a missing backup.
    fn from_backup(error: &BackupError) -> Self {
        match error {
            BackupError::NotFound { name: _ } | BackupError::InvalidName { value: _ } => {
                Self::Missing
            }
            BackupError::State(_)
            | BackupError::Crypto(_)
            | BackupError::Malformed { name: _ }
            | BackupError::Config(_)
            | _ => {
                tracing::error!(%error, "backup store failed");
                Self::Failed
            }
        }
    }
}

/// Runs `work` on the blocking pool.
///
/// # Errors
///
/// Returns the store error of `work`, or `Failed` when the task did not finish.
// NOT cancel-safe: dropped, `work` still runs to its end on the blocking pool.
async fn blocking<T, F>(work: F) -> Result<T, StoreError>
where
    F: FnOnce() -> Result<T, StoreError> + Send + 'static,
    T: Send + 'static,
{
    spawn_blocking(work).await.unwrap_or_else(|error| {
        tracing::error!(%error, "backup task failed");
        Err(StoreError::Failed)
    })
}

/// Every backup of `router`, newest first.
///
/// # Errors
///
/// Returns why the store could not be listed.
// cancel-safe: reads only.
pub(crate) async fn list(
    services: &BackupServices,
    router: &str,
) -> Result<Vec<BackupInfo>, StoreError> {
    let store = Arc::clone(services.store());
    let id = router.to_owned();
    blocking(move || {
        store
            .list(&id)
            .map_err(|error| StoreError::from_backup(&error))
    })
    .await
}

/// The backup `name` of `router`, decrypted.
///
/// # Errors
///
/// Returns `Missing` for an unknown backup, else why it could not be read.
// cancel-safe: reads only.
pub(crate) async fn read(
    services: &BackupServices,
    router: &str,
    name: &str,
) -> Result<SecretString, StoreError> {
    let store = Arc::clone(services.store());
    let (id, file) = (router.to_owned(), name.to_owned());
    blocking(move || {
        store
            .get(&id, &file)
            .map_err(|error| StoreError::from_backup(&error))
    })
    .await
}

/// Stores `text` as a backup of `router` for `reason`; the store names it, and a
/// second backup in the same second gets a name of its own.
///
/// # Errors
///
/// Returns why the store failed.
// NOT cancel-safe: the backup may be written after the caller stopped waiting.
pub(crate) async fn keep(
    services: &BackupServices,
    router: &str,
    (reason, text): (String, SecretString),
) -> Result<BackupInfo, StoreError> {
    let store = Arc::clone(services.store());
    let id = router.to_owned();
    blocking(move || {
        store
            .create(&id, &reason, &text)
            .map_err(|error| StoreError::from_backup(&error))
    })
    .await
}

/// Deletes the backup `name` of `router`.
///
/// # Errors
///
/// Returns `Missing` for an unknown backup, else why it could not be deleted.
// NOT cancel-safe: the file may be removed after the caller stopped waiting.
pub(crate) async fn delete(
    services: &BackupServices,
    router: &str,
    name: &str,
) -> Result<(), StoreError> {
    let store = Arc::clone(services.store());
    let (id, file) = (router.to_owned(), name.to_owned());
    blocking(move || {
        store
            .delete(&id, &file)
            .map_err(|error| StoreError::from_backup(&error))
    })
    .await
}

/// One action on backups: its audit id and the permissions it needs on the router.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Act {
    /// Stable audit action id.
    action: &'static str,
    /// Permissions the action needs.
    permissions: &'static [Permission],
}

/// A backup of the saved configuration (`Write`).
pub(crate) const CREATE: Act = Act::new("web.config_backup_create", &[Permission::Write]);
/// A startup-configuration file stored as a backup (`Write`).
pub(crate) const UPLOAD: Act = Act::new("web.config_backup_upload", &[Permission::Write]);
/// A backup removed (`Destructive`).
pub(crate) const DELETE: Act = Act::new("web.config_backup_delete", &[Permission::Destructive]);
/// A backup downloaded without its secrets (`Read`).
pub(crate) const DOWNLOAD: Act = Act::new("web.config_backup_download", &[Permission::Read]);
/// A backup downloaded with its secrets (`RevealSecrets`).
pub(crate) const DOWNLOAD_FULL: Act = Act::new(
    "web.config_backup_download",
    &[Permission::Read, Permission::RevealSecrets],
);
/// A backup restored as the router's saved configuration (`Destructive` and `Migrate`).
pub(crate) const RAW_RESTORE: Act = Act::new(
    "web.config_raw_restore",
    &[Permission::Destructive, Permission::Migrate],
);

impl Act {
    /// The action `action`, needing `permissions`.
    const fn new(action: &'static str, permissions: &'static [Permission]) -> Self {
        Self {
            action,
            permissions,
        }
    }

    /// Stable audit action id.
    pub(crate) const fn action(self) -> &'static str {
        self.action
    }

    /// Opens the action on the backups of `router` for `user`.
    ///
    /// # Errors
    ///
    /// The answer instead: 404 or 503 when the router is not visible or no backups are
    /// attached, the audited 403 when the role lacks a permission.
    // NOT cancel-safe: a refusal queues an audit entry that may be written after the future is
    // dropped; otherwise it only reads.
    pub(crate) async fn open<'call>(
        self,
        state: &'call WebState,
        user: &'call CurrentUser,
        router: &'call str,
    ) -> Result<Opened<'call>, Answer> {
        let target = context::target(state, user, router)
            .await
            .map_err(context::Refusal::status)?;
        let Some(services) = target.fleet().backups().cloned() else {
            return Err(StatusCode::SERVICE_UNAVAILABLE.into_response().into());
        };
        if !allowed(user, router, self.permissions) {
            Record::on_router(self.action, router, "backups".to_owned())
                .append(state, user, "forbidden")
                .await;
            return Err(errors::response(Kind::Forbidden, fragment_shell(user.locale())).into());
        }
        Ok(Opened {
            state,
            user,
            router,
            services,
            act: self,
        })
    }
}

/// An action opened on the backups of one router.
pub(crate) struct Opened<'call> {
    /// Web services.
    state: &'call WebState,
    /// The signed-in user.
    user: &'call CurrentUser,
    /// Router profile id.
    router: &'call str,
    /// The backup store and its retention.
    services: BackupServices,
    /// The action.
    act: Act,
}

impl<'call> Opened<'call> {
    /// The backup store and its retention.
    pub(crate) const fn services(&self) -> &BackupServices {
        &self.services
    }

    /// Router profile id.
    pub(crate) const fn router(&self) -> &'call str {
        self.router
    }

    /// Web services.
    pub(crate) const fn state(&self) -> &'call WebState {
        self.state
    }

    /// The signed-in user.
    pub(crate) const fn user(&self) -> &'call CurrentUser {
        self.user
    }

    /// Audits how the action on `target` ended, with `params` that hold names and facts
    /// the page chose, never a value from a backup.
    // NOT cancel-safe: an abandoned append may still be written.
    pub(crate) async fn finish(self, (target, params): (&str, Value), outcome: &str) {
        Record::on_router(self.act.action, self.router, target.to_owned())
            .with_params(params)
            .append(self.state, self.user, outcome)
            .await;
    }

    /// An answer that ends the action audited as `outcome`.
    // NOT cancel-safe: an abandoned append may still be written.
    pub(crate) async fn refuse(self, target: &str, outcome: &str, answer: Response) -> Answer {
        self.finish((target, Value::Null), outcome).await;
        answer.into()
    }
}
