//! A family of pages and the words of its outcomes.
//!
//! The command explorer and the consoles run raw commands, so their messages speak of
//! commands; a domain page runs a curated operation, so its messages speak of changes. A
//! page family picks its [`Family`] once and passes it to the confirmations (which changes
//! ask first and in which words, `confirm::Stakes`) and to the outcomes.

use kcc_i18n::{bundle::MessageKey, keys};

/// A family of pages: its confirmation policy (`confirm::Stakes::guard`) and its messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Family {
    /// The command explorer and the consoles: every change asks, messages speak of
    /// commands.
    Commands,
    /// The domain pages: management and destructive changes ask, messages speak of
    /// changes.
    Changes,
}

impl Family {
    /// Headline of a completed request; `unsaved` when the router has unsaved changes now.
    pub(crate) const fn done(self, unsaved: bool) -> MessageKey {
        match (self, unsaved) {
            (Self::Commands, false) => keys::WEB_EXPLORER_DONE,
            (Self::Commands, true) => keys::WEB_EXPLORER_DONE_UNSAVED,
            (Self::Changes, false) => keys::WEB_KIT_DONE,
            (Self::Changes, true) => keys::WEB_KIT_DONE_UNSAVED,
        }
    }

    /// Headline of a change after which the router's state is unknown: a reboot, a reset.
    pub(crate) const fn done_terminal(self) -> MessageKey {
        match self {
            Self::Commands => keys::WEB_EXPLORER_DONE,
            Self::Changes => keys::WEB_KIT_DONE_TERMINAL,
        }
    }

    /// Headline of a request stopped before anything was sent.
    pub(crate) const fn invalid(self) -> MessageKey {
        match self {
            Self::Commands => keys::WEB_EXPLORER_INVALID,
            Self::Changes => keys::WEB_KIT_INVALID,
        }
    }

    /// The router refused the request.
    pub(crate) const fn rejected(self) -> MessageKey {
        match self {
            Self::Commands => keys::WEB_EXPLORER_REJECTED,
            Self::Changes => keys::WEB_KIT_REJECTED,
        }
    }

    /// Another session changed the router first.
    pub(crate) const fn conflict(self) -> MessageKey {
        match self {
            Self::Commands => keys::WEB_EXPLORER_CONFLICT,
            Self::Changes => keys::WEB_KIT_CONFLICT,
        }
    }

    /// The request failed for another reason.
    pub(crate) const fn failed(self) -> MessageKey {
        match self {
            Self::Commands => keys::WEB_EXPLORER_FAILED,
            Self::Changes => keys::WEB_KIT_FAILED,
        }
    }

    /// The router did not answer.
    pub(crate) const fn unreachable(self) -> MessageKey {
        match self {
            Self::Commands => keys::WEB_EXPLORER_UNREACHABLE,
            Self::Changes => keys::WEB_KIT_UNREACHABLE,
        }
    }

    /// The router does not know the resource.
    pub(crate) const fn not_found(self) -> MessageKey {
        match self {
            Self::Commands => keys::WEB_EXPLORER_NOT_FOUND,
            Self::Changes => keys::WEB_KIT_NOT_FOUND,
        }
    }
}
