//! Conversions from application errors into CLI failures.

use std::io;

use kcc_app::{
    accounts::AccountError,
    api_keys::ApiKeyError,
    audit::AuditError,
    backups::BackupError,
    permissions::{PermissionError, assignment::GrantError},
    persist::StateError,
    secrets::CryptoError,
    settings::ConfigError,
};
use kcc_i18n::keys;

use super::exit::{Exit, Failure, denied};

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
