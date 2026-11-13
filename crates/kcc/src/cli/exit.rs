//! Exit codes and the one failure type every command returns.

use core::fmt;

use fluent_bundle::FluentArgs;
use kcc_app::{
    credentials::CredentialError, registry::RegistryError, secrets::files::SecretFileError,
    workflow::WorkflowError,
};
use kcc_catalog::ValidationIssue;
use kcc_domain::{
    DomainError,
    configuration::{ModeUnknown, bracket::ArmedFate, recovery},
    interfaces::InterfaceChangeError,
};
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};
use kcc_rci::RciError;

use super::{issues::issue_sentence, secret::secret_file_failure};

/// The documented process exit codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Exit {
    /// 1: any other failure.
    Generic,
    /// 2: invalid command line or missing input.
    Usage,
    /// 3: router or account authentication failed.
    Auth,
    /// 4: catalog or input validation rejected the request; nothing was sent.
    Validation,
    /// 5: the router is busy or changed concurrently.
    Conflict,
    /// 6: the router answered with an error or could not be reached.
    Router,
    /// 7: a batch partly failed.
    Partial,
    /// 10: permission, scope, confirmation or firmware policy refused the action.
    Policy,
}

impl Exit {
    /// The process exit code.
    pub(crate) const fn code(self) -> u8 {
        match self {
            Self::Generic => 1,
            Self::Usage => 2,
            Self::Auth => 3,
            Self::Validation => 4,
            Self::Conflict => 5,
            Self::Router => 6,
            Self::Partial => 7,
            Self::Policy => 10,
        }
    }

    /// The stable machine name used by `--json` error output.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Generic => "error",
            Self::Usage => "usage",
            Self::Auth => "auth",
            Self::Validation => "validation",
            Self::Conflict => "conflict",
            Self::Router => "router",
            Self::Partial => "partial",
            Self::Policy => "policy",
        }
    }

    /// The localized headline of this kind of failure.
    const fn headline(self) -> MessageKey {
        match self {
            Self::Generic => keys::CLI_ERROR_GENERIC,
            Self::Usage => keys::CLI_ERROR_USAGE,
            Self::Auth => keys::CLI_ERROR_AUTH,
            Self::Validation => keys::CLI_ERROR_VALIDATION,
            Self::Conflict => keys::CLI_ERROR_CONFLICT,
            Self::Router => keys::CLI_ERROR_ROUTER,
            Self::Partial => keys::CLI_ERROR_PARTIAL,
            Self::Policy => keys::CLI_ERROR_POLICY,
        }
    }
}

/// What a failure says beyond its headline.
#[derive(Debug)]
pub(crate) enum Detail {
    /// Nothing more.
    None,
    /// Display-safe English text from a typed error (never router bodies or secrets).
    Text(String),
    /// Catalog validation issues, rendered in the output locale.
    Issues(Vec<ValidationIssue>),
    /// A localized message with its arguments.
    Message(MessageKey, Vec<(&'static str, String)>),
}

/// A command failure: its exit code and a secret-free explanation.
#[derive(Debug)]
pub(crate) struct Failure {
    /// Exit code family.
    exit: Exit,
    /// Explanation.
    detail: Detail,
    /// A headline more precise than the exit family's, such as a change the router
    /// accepted but did not apply.
    headline: Option<MessageKey>,
    /// The router's recovery timer may still be armed.
    armed: bool,
}

/// Command result.
pub(crate) type Outcome<T = ()> = Result<T, Failure>;

impl Failure {
    /// Preserves the error family while exposing an unfinished recovery bracket: an armed
    /// fate headlines what may still be armed, a refused arm says nothing was applied, and
    /// any other failure keeps its own explanation.
    pub(crate) fn recovery(error: recovery::Failure<Self>) -> Self {
        let outcome = (error.fate(), error.message_key());
        let source = error.into_source();
        match outcome {
            (Some(fate), _) => Self::armed(source.exit(), fate),
            (None, Some(key)) => source.headlined(key),
            (None, None) => source,
        }
    }

    /// A failure that left the recovery timer armed after `fate`, headlined by it.
    pub(crate) const fn armed(exit: Exit, fate: ArmedFate) -> Self {
        Self {
            exit,
            detail: Detail::None,
            headline: Some(fate.message_key()),
            armed: true,
        }
    }

    /// Whether this failure reports an armed recovery timer.
    pub(crate) const fn fail_safe_armed(&self) -> bool {
        self.armed
    }

    /// Preserves the specific explanation while changing the process outcome family.
    pub(crate) const fn at_exit(mut self, exit: Exit) -> Self {
        self.exit = exit;
        self
    }
    /// A failure with a detail.
    pub(crate) const fn new(exit: Exit, detail: Detail) -> Self {
        Self {
            exit,
            detail,
            headline: None,
            armed: false,
        }
    }

    /// The same failure under the headline `key` instead of the exit family's.
    const fn headlined(mut self, key: MessageKey) -> Self {
        self.headline = Some(key);
        self
    }

    /// A failure explained by one localized message.
    pub(crate) fn message(exit: Exit, key: MessageKey, args: &[(&'static str, &str)]) -> Self {
        Self::new(
            exit,
            Detail::Message(
                key,
                args.iter()
                    .map(|&(name, value)| (name, value.to_owned()))
                    .collect(),
            ),
        )
    }

    /// A failure whose localized headline fully explains the outcome.
    pub(crate) const fn headline_only(exit: Exit, key: MessageKey) -> Self {
        Self::new(exit, Detail::None).headlined(key)
    }

    /// A failure explained by display-safe text.
    pub(crate) fn text(exit: Exit, text: &(impl fmt::Display + ?Sized)) -> Self {
        Self::new(exit, Detail::Text(text.to_string()))
    }

    /// The exit code family.
    pub(crate) const fn exit(&self) -> Exit {
        self.exit
    }

    /// The localized headline.
    pub(crate) fn headline(&self, locale: Locale) -> String {
        tr(
            locale,
            self.headline.unwrap_or_else(|| self.exit.headline()),
            None,
        )
    }

    /// The localized detail lines.
    pub(crate) fn details(&self, locale: Locale) -> Vec<String> {
        match &self.detail {
            Detail::None => Vec::new(),
            Detail::Text(text) => vec![text.clone()],
            Detail::Issues(issues) => issues
                .iter()
                .map(|issue| issue_sentence(locale, issue))
                .collect(),
            Detail::Message(key, values) => {
                let mut args = FluentArgs::new();
                for (name, value) in values {
                    args.set(*name, value.clone());
                }
                vec![tr(locale, *key, Some(&args))]
            }
        }
    }
}

impl From<RciError> for Failure {
    fn from(error: RciError) -> Self {
        let exit = match &error {
            RciError::Auth(_) => Exit::Auth,
            RciError::Validation => Exit::Validation,
            RciError::Policy => Exit::Policy,
            RciError::Transport
            | RciError::Timeout
            | RciError::Http { status: _ }
            | RciError::Rci {
                pointer: _,
                code: _,
                ident: _,
                message: _,
            }
            | RciError::NotFound
            | RciError::MethodNotAllowed
            | RciError::BodyTooLarge
            | RciError::Decode
            | _ => Exit::Router,
        };
        Self::text(exit, &error)
    }
}

impl From<ModeUnknown> for Failure {
    fn from(_error: ModeUnknown) -> Self {
        Self::headline_only(Exit::Policy, keys::MANAGEMENT_MODE_UNKNOWN)
    }
}

impl From<InterfaceChangeError> for Failure {
    fn from(error: InterfaceChangeError) -> Self {
        Self::text(Exit::Router, &error)
    }
}

impl From<RegistryError> for Failure {
    fn from(error: RegistryError) -> Self {
        let exit = match error {
            RegistryError::Rci(inner) => return inner.into(),
            RegistryError::PermissionDenied { router } => return denied(&router),
            RegistryError::CredentialFile { path: _, source: _ } => Exit::Auth,
            RegistryError::CredentialPermissions { path } => {
                return secret_file_failure(&SecretFileError::Permissions { path });
            }
            RegistryError::InvalidProfile { reason: _ } => Exit::Validation,
            RegistryError::AlreadyExists { id: _ } => Exit::Conflict,
            RegistryError::ConfigDefined { id: _ } => Exit::Policy,
            RegistryError::NotFound { id: _ } => Exit::Usage,
            RegistryError::State(_) | RegistryError::ProfileLock | _ => Exit::Generic,
        };
        Self::text(exit, &error)
    }
}

impl From<CredentialError> for Failure {
    fn from(error: CredentialError) -> Self {
        Self::text(Exit::Auth, &error)
    }
}

impl From<WorkflowError> for Failure {
    fn from(error: WorkflowError) -> Self {
        let exit = match error {
            WorkflowError::Rci(inner) => return inner.into(),
            WorkflowError::Registry(inner) => return inner.into(),
            WorkflowError::PermissionDenied { router } => return denied(&router),
            WorkflowError::CatalogValidation { issues } => {
                return Self::new(Exit::Validation, Detail::Issues(issues));
            }
            WorkflowError::SecretCommand(_) => Exit::Validation,
            WorkflowError::RouterBusy { actor: _ } | WorkflowError::Conflict { agent: _ } => {
                Exit::Conflict
            }
            WorkflowError::VerificationFailed { field: _ } => {
                return Self::text(Exit::Router, &error).headlined(keys::CLI_ERROR_NOT_APPLIED);
            }
            WorkflowError::InvalidResponse | WorkflowError::SaveTimeout => Exit::Router,
            WorkflowError::State(_) | WorkflowError::Backup(_) | WorkflowError::Audit(_) | _ => {
                Exit::Generic
            }
        };
        Self::text(exit, &error)
    }
}

impl From<DomainError> for Failure {
    fn from(error: DomainError) -> Self {
        let exit = match error {
            DomainError::Rci(inner) => return inner.into(),
            DomainError::Workflow(inner) => return inner.into(),
            DomainError::Validation { issues } => {
                return Self::new(Exit::Validation, Detail::Issues(issues));
            }
            DomainError::ProtectedAccount => {
                return Self::message(Exit::Policy, keys::CLI_PROFILE_LOGIN_PROTECTED, &[]);
            }
            DomainError::FirewallVerificationFailed => {
                return Self::message(Exit::Router, keys::CLI_ERROR_FIREWALL_VERIFICATION, &[]);
            }
            DomainError::PermissionDenied | DomainError::ConfirmationRequired => Exit::Policy,
            DomainError::InvalidResponse
            | DomainError::SafetyAbort
            | DomainError::RouteCountMismatch => Exit::Router,
            DomainError::ConfirmationMismatch
            | DomainError::StaticLeaseOutsidePool
            | DomainError::StaticLeaseAddressInUse
            | DomainError::InvalidCliToken
            | _ => Exit::Validation,
        };
        Self::text(exit, &error)
    }
}

/// The permission or scope refusal of `router`.
pub(crate) fn denied(router: &str) -> Failure {
    Failure::message(Exit::Policy, keys::CLI_REFUSED, &[("router", router)])
}
