//! What a page says when a router read fails: the class of the failure in the user's
//! words, and a value-free technical detail where kcc has one.
//!
//! The detail is the transport cause, the router's error ident and code, or where in the
//! answer decoding stopped; it never carries a value from the router's answer. Pages show
//! it untranslated under a localized "Details" label.

use fluent_bundle::FluentArgs;
use kcc_app::registry::RegistryError;
use kcc_domain::DomainError;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};
use kcc_rci::RciError;

use super::{family::Family, outcome::Failure};

/// Why a router read failed, as a page shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReadProblem {
    /// The message naming the failure class.
    key: MessageKey,
    /// The HTTP status the message names, for an HTTP error.
    status: Option<u16>,
    /// Untranslated technical detail, free of router values.
    detail: Option<String>,
}

impl From<MessageKey> for ReadProblem {
    /// A problem told by `key` alone.
    fn from(key: MessageKey) -> Self {
        Self {
            key,
            status: None,
            detail: None,
        }
    }
}

impl ReadProblem {
    /// `self` with `detail` shown under the "Details" label.
    fn with_detail(self, detail: String) -> Self {
        Self {
            detail: Some(detail),
            ..self
        }
    }

    /// The same problem told by `key`, for a page with its own words for the class.
    pub(crate) fn saying(self, key: MessageKey) -> Self {
        Self { key, ..self }
    }

    /// The message naming the failure class.
    #[cfg(test)]
    pub(crate) const fn key(&self) -> MessageKey {
        self.key
    }

    /// Untranslated technical detail, if any.
    pub(crate) fn detail(&self) -> Option<&str> {
        self.detail.as_deref()
    }

    /// The message in `locale`.
    pub(crate) fn text(&self, locale: Locale) -> String {
        let mut args = FluentArgs::new();
        if let Some(status) = self.status {
            args.set("status", status.to_string());
        }
        tr(locale, self.key, Some(&args))
    }

    /// The failure of a request that stopped at this read, audited as `audit`.
    pub(crate) fn failure(&self, locale: Locale, audit: &'static str) -> Failure {
        Failure::new(self.text(locale), audit).with_detail(self.detail.clone())
    }
}

/// What a page says when a read through a domain failed with `error`, in `family`'s
/// words.
pub(crate) fn read_problem(family: Family, error: &DomainError) -> ReadProblem {
    match error {
        DomainError::Rci(rci) => rci_problem(family, rci),
        DomainError::UnreadableAnswer(detail) => {
            ReadProblem::from(keys::WEB_KIT_UNREADABLE).with_detail(detail.to_string())
        }
        DomainError::InvalidResponse => ReadProblem::from(keys::WEB_KIT_UNREADABLE),
        DomainError::Validation { issues: _ }
        | DomainError::ConfirmationMismatch
        | DomainError::StaticLeaseOutsidePool
        | DomainError::StaticLeaseAddressInUse
        | DomainError::ProtectedAccount
        | DomainError::InvalidCliToken
        | DomainError::ConfirmationRequired
        | DomainError::PermissionDenied
        | DomainError::Workflow(_)
        | DomainError::SafetyAbort
        | DomainError::RouteCountMismatch
        | DomainError::FirewallRuleAbsent
        | DomainError::FirewallVerificationFailed
        | DomainError::EntwareDriveInUse
        | _ => ReadProblem::from(family.failed()),
    }
}

/// What a domain page says when a read through a domain failed with `error`.
pub(crate) fn domain_problem(error: &DomainError) -> ReadProblem {
    read_problem(Family::Changes, error)
}

/// What a page says when kcc could not get a client for the router: the router error
/// when one was the cause, otherwise that the router did not answer.
pub(crate) fn registry_problem(family: Family, error: &RegistryError) -> ReadProblem {
    let RegistryError::Rci(rci) = error else {
        return ReadProblem::from(family.unreachable());
    };
    rci_problem(family, rci)
}

/// What a page says when a router request failed with `error`, in `family`'s words.
pub(crate) fn rci_problem(family: Family, error: &RciError) -> ReadProblem {
    match error {
        RciError::Transport(cause) => {
            ReadProblem::from(family.unreachable()).with_detail(cause.to_string())
        }
        RciError::Timeout => ReadProblem::from(keys::ERRORS_TIMEOUT),
        RciError::Auth(_) => ReadProblem::from(keys::ERRORS_ROUTER_AUTH),
        RciError::Http { status } => ReadProblem {
            status: Some(*status),
            ..ReadProblem::from(keys::WEB_KIT_HTTP_ERROR)
        },
        RciError::Rci {
            pointer: _,
            code,
            ident,
            message: _,
        } => ReadProblem::from(keys::WEB_KIT_ROUTER_ERROR).with_detail(format!("{ident} {code}")),
        RciError::NotFound | RciError::MethodNotAllowed => ReadProblem::from(family.not_found()),
        RciError::BodyTooLarge => ReadProblem::from(keys::WEB_KIT_TOO_LARGE),
        RciError::Policy => ReadProblem::from(keys::WEB_KIT_POLICY),
        RciError::Decode(detail) => {
            ReadProblem::from(keys::WEB_KIT_UNREADABLE).with_detail(detail.to_string())
        }
        RciError::Cancelled | RciError::Validation | _ => ReadProblem::from(family.failed()),
    }
}

#[cfg(test)]
mod tests;
