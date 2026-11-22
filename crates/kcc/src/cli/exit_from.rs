//! Conversions from application errors into CLI failures.

use std::io;

use kcc_app::{
    accounts::AccountError,
    api_keys::ApiKeyError,
    audit::AuditError,
    backups::BackupError,
    composition::CoreError,
    permissions::{PermissionError, assignment::GrantError},
    persist::StateError,
    secrets::CryptoError,
    settings::ConfigError,
};
use kcc_i18n::keys;

use super::exit::{Exit, Failure, denied};
use crate::server_error::ServerError;

impl From<StateError> for Failure {
    fn from(error: StateError) -> Self {
        Self::text(Exit::Generic, &error)
    }
}

impl From<AuditError> for Failure {
    fn from(error: AuditError) -> Self {
        Self::text(Exit::Generic, &error)
    }
}

impl From<BackupError> for Failure {
    fn from(error: BackupError) -> Self {
        let exit = match &error {
            BackupError::NotFound { name: _ } | BackupError::InvalidName { value: _ } => {
                Exit::Usage
            }
            BackupError::State(_)
            | BackupError::Crypto(_)
            | BackupError::Malformed { name: _ }
            | BackupError::Config(_)
            | _ => Exit::Generic,
        };
        Self::text(exit, &error)
    }
}

impl From<CoreError> for Failure {
    fn from(error: CoreError) -> Self {
        match error {
            CoreError::Key(source) => source.into(),
            CoreError::Credentials(source) => source.into(),
            CoreError::Registry(source) => source.into(),
            CoreError::Audit(source) => source.into(),
            other => Self::text(Exit::Generic, &other),
        }
    }
}

impl From<CryptoError> for Failure {
    fn from(error: CryptoError) -> Self {
        Self::text(Exit::Generic, &error)
    }
}

impl From<ConfigError> for Failure {
    fn from(error: ConfigError) -> Self {
        Self::text(Exit::Generic, &error)
    }
}

impl From<PermissionError> for Failure {
    fn from(error: PermissionError) -> Self {
        Self::text(Exit::Generic, &error)
    }
}

impl From<GrantError> for Failure {
    fn from(error: GrantError) -> Self {
        match error {
            GrantError::Forbidden => denied("-"),
            GrantError::UnknownRole { name } => {
                Self::message(Exit::Usage, keys::CLI_NOT_FOUND, &[("name", &name)])
            }
            GrantError::Roles(roles) => roles.into(),
            _ => Self::text(Exit::Generic, &error),
        }
    }
}

impl From<AccountError> for Failure {
    fn from(error: AccountError) -> Self {
        let exit = match error {
            AccountError::Grant(grant) => return grant.into(),
            AccountError::InvalidUsername
            | AccountError::InvalidPasswordLength
            | AccountError::InvalidPasswordCharacters
            | AccountError::PasswordEqualsUsername => Exit::Validation,
            AccountError::DuplicateAccount => Exit::Conflict,
            AccountError::LastAdmin
            | AccountError::PermissionDenied
            | AccountError::SelfResetRequiresCurrentPassword
            | AccountError::AdminResetRequiresAdmin => Exit::Policy,
            AccountError::State(_)
            | AccountError::Crypto(_)
            | AccountError::PasswordHash
            | AccountError::StoredPasswordHash
            | _ => Exit::Generic,
        };
        Self::text(exit, &error)
    }
}

impl From<ApiKeyError> for Failure {
    fn from(error: ApiKeyError) -> Self {
        let exit = match error {
            ApiKeyError::Grant(grant) => return grant.into(),
            ApiKeyError::DuplicateName => Exit::Conflict,
            ApiKeyError::InvalidName | ApiKeyError::InvalidExpiry => Exit::Validation,
            ApiKeyError::State(_) | ApiKeyError::Generation | _ => Exit::Generic,
        };
        Self::text(exit, &error)
    }
}

impl From<io::Error> for Failure {
    fn from(error: io::Error) -> Self {
        Self::text(Exit::Generic, &error)
    }
}

impl From<serde_json::Error> for Failure {
    fn from(error: serde_json::Error) -> Self {
        Self::text(Exit::Validation, &error)
    }
}

impl From<ServerError> for Failure {
    fn from(error: ServerError) -> Self {
        let message = |key, args: &[(&'static str, &str)]| Self::message(Exit::Generic, key, args);
        match &error {
            ServerError::NoConfigPath => message(keys::CLI_SERVE_NO_CONFIG_PATH, &[]),
            ServerError::ServerLock { dir, source } => message(
                keys::CLI_SERVE_LOCKED,
                &[
                    ("path", &dir.display().to_string()),
                    ("reason", &source.to_string()),
                ],
            ),
            ServerError::TlsKeyReadable { path } => message(
                keys::ERRORS_SECRET_FILE_PERMISSIONS,
                &[("path", &path.display().to_string())],
            ),
            ServerError::LogMetricsUnavailable => {
                message(keys::CLI_SERVE_LOG_METRICS_UNAVAILABLE, &[])
            }
            ServerError::UnknownStdioRole(role) => message(
                keys::CLI_SERVE_STDIO_ROLE_UNKNOWN,
                &[("name", &format!("{role:?}"))],
            ),
            ServerError::UnsupportedLocale => message(keys::CLI_SERVE_LOCALE_UNSUPPORTED, &[]),
            ServerError::Bind {
                address,
                port,
                source,
            } => message(
                keys::CLI_SERVE_BIND,
                &[
                    ("address", address),
                    ("port", &port.to_string()),
                    ("reason", &source.to_string()),
                ],
            ),
            ServerError::AuditWriterTerminated => {
                message(keys::CLI_SERVE_AUDIT_WRITER_TERMINATED, &[])
            }
            ServerError::Start { listener, reason } => message(
                keys::CLI_SERVE_LISTENER_START,
                &[("name", listener), ("reason", reason)],
            ),
            ServerError::Rebind { listener, reason } => message(
                keys::CLI_SERVE_REBIND,
                &[("name", listener), ("reason", reason)],
            ),
            ServerError::ListenerTask => message(keys::CLI_SERVE_LISTENER_TASK, &[]),
            ServerError::Config(_)
            | ServerError::Kit(_)
            | ServerError::State(_)
            | ServerError::TlsKey(_)
            | ServerError::Core(_)
            | ServerError::Registry(_)
            | ServerError::Roles(_)
            | ServerError::McpSettings(_)
            | ServerError::Jobs(_)
            | ServerError::Reload(_)
            | ServerError::Logs(_)
            | ServerError::Metrics(_)
            | ServerError::Listener(_) => Self::text(Exit::Generic, &error),
        }
    }
}
