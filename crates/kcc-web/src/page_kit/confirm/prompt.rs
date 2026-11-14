//! The kit's prompt: the dialog asking for exactly what a request's guard checks.

use axum::response::Response;
use fluent_bundle::FluentArgs;
use kcc_i18n::{bundle::tr, keys, locale::Locale};

use super::{Ask, Dialog, FAIL_SAFE_MINUTES, Guard, Prompt, Resubmit, Saved, Typed, Words};
use crate::page_kit::family::Family;

impl Prompt {
    /// Asks on `router` for the confirmation `guard` checks, in `family`'s words; only the
    /// gate's own decision makes one (`Stakes::ask`).
    pub(in crate::page_kit) fn new(family: Family, guard: Guard, router: &str) -> Self {
        Self {
            family,
            guard,
            router: router.to_owned(),
            wrong_name: false,
            persists: false,
            persisted_paths: Vec::new(),
        }
    }

    /// Reports that the typed router name did not match.
    pub(in crate::page_kit) const fn with_wrong_name(mut self, wrong_name: bool) -> Self {
        self.wrong_name = wrong_name;
        self
    }

    /// Labels a request the router persists at once (no save, no fail-safe rollback).
    pub(crate) const fn with_persists(mut self, persists: bool) -> Self {
        self.persists = persists;
        self
    }

    /// Labels persisted leaf paths when the rest of the request still needs a save.
    pub(crate) fn with_persisted_paths(mut self, persisted_paths: Vec<String>) -> Self {
        self.persisted_paths = persisted_paths;
        self
    }

    /// The dialog, shown in the shared `<dialog>`; confirming sends `resubmit`.
    pub(crate) fn render(self, resubmit: Resubmit, locale: Locale) -> Response {
        let mut args = FluentArgs::new();
        args.set("router", self.router.clone());
        args.set("name", self.router.clone());
        args.set("minutes", FAIL_SAFE_MINUTES.to_string());
        let (title, unsaved_text) = self.guard.words(self.family);
        // The router saves such a change itself, so the dialog does not call it unsaved.
        let text = if self.persists && self.guard == Guard::Write {
            keys::WEB_EXPLORER_CONFIRM_PERSIST_TEXT
        } else if !self.persisted_paths.is_empty() && self.guard == Guard::Write {
            keys::WEB_EXPLORER_CONFIRM_MIXED_TEXT
        } else {
            unsaved_text
        };
        let saved = if self.persists {
            Saved::Persists
        } else if self.persisted_paths.is_empty() {
            Saved::Unsaid
        } else {
            let mut mixed_args = FluentArgs::new();
            mixed_args.set("paths", self.persisted_paths.join(", "));
            Saved::Mixed(tr(
                locale,
                keys::WEB_EXPLORER_MIXED_PERSISTENCE_BEFORE,
                Some(&mixed_args),
            ))
        };
        let button = match self.family {
            Family::Commands => keys::WEB_EXPLORER_CONFIRM,
            Family::Changes => keys::WEB_KIT_CONFIRM,
        };
        let ask = if self.guard.needs_name() {
            // The timer's text does not ask for the name, so the field says what to type.
            let help = if self.guard == Guard::DestructiveManagement {
                tr(locale, keys::WEB_ADMIN_CONFIRM_HELP, Some(&args))
            } else {
                String::new()
            };
            let error = if self.wrong_name {
                tr(locale, keys::WEB_EXPLORER_CONFIRM_NAME_ERROR, Some(&args))
            } else {
                String::new()
            };
            Ask::Typed(Typed::router(locale).with_help(help).with_error(error))
        } else {
            Ask::Acknowledge
        };
        let words = Words::new(
            tr(locale, title, Some(&args)),
            tr(locale, text, Some(&args)),
            tr(locale, button, None),
        );
        Dialog::new(locale, words, resubmit)
            .with_text_key(text)
            .saying(saved)
            .asking(ask)
            .show()
    }
}
