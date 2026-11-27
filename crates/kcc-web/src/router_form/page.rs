//! The router form page: the add form, the edit form, or the read-only view of a
//! `kcc.toml` profile.

use askama::Template;
use fluent_bundle::FluentArgs;
use kcc_app::{
    credentials::{CredentialKind, CredentialStore},
    registry::ManagedRouterProfile,
};
use kcc_i18n::{bundle::tr, keys};

use super::{Draft, FieldErrors};
use crate::page::{Localize as _, Shell};

/// Which credentials a profile already has, for the notes beside the empty secret fields.
/// Only presence is known here, never a value or its length.
#[derive(Debug, Clone, Default)]
pub(crate) struct Stored {
    /// The kinds the profile holds: a password file, a sealed token, a sealed read-only
    /// password.
    kinds: Vec<CredentialKind>,
    /// The profile has a read-only polling login.
    reader: bool,
}

impl Stored {
    /// What `profile` has; a sealed record that cannot be checked counts as absent.
    pub(crate) fn of(store: &CredentialStore, profile: &ManagedRouterProfile) -> Self {
        let sealed = |kind| matches!(store.exists(&profile.id, kind), Ok(true));
        let kinds = [
            (CredentialKind::Password, profile.password_file.is_some()),
            (CredentialKind::Token, sealed(CredentialKind::Token)),
            (
                CredentialKind::ReadPassword,
                sealed(CredentialKind::ReadPassword),
            ),
        ]
        .into_iter()
        .filter_map(|(kind, held)| held.then_some(kind))
        .collect();
        Self {
            kinds,
            reader: profile.read_login.is_some(),
        }
    }

    /// The profile has a management password.
    fn password(&self) -> bool {
        self.kinds.contains(&CredentialKind::Password)
    }

    /// A sealed token exists.
    fn token(&self) -> bool {
        self.kinds.contains(&CredentialKind::Token)
    }

    /// The profile has a read-only polling login.
    const fn reader(&self) -> bool {
        self.reader
    }

    /// A sealed read-only password exists.
    fn read(&self) -> bool {
        self.kinds.contains(&CredentialKind::ReadPassword)
    }
}

/// The add or edit form, or the read-only view of a `kcc.toml` profile.
#[derive(Template)]
#[template(path = "pages/router_form.html")]
pub(crate) struct FormPage {
    /// Page shell.
    shell: Shell,
    /// Page title.
    title: String,
    /// Whether an existing profile is edited (the id is fixed).
    editing: bool,
    /// Whether the profile comes from `kcc.toml` and is shown read-only.
    read_only: bool,
    /// Values to show.
    draft: Draft,
    /// Field errors.
    errors: FieldErrors,
    /// The credentials the edited profile has.
    stored: Stored,
}

impl FormPage {
    /// The add form.
    pub(crate) fn add(shell: Shell, draft: Draft, errors: FieldErrors) -> Self {
        let title = tr(shell.locale(), keys::WEB_ROUTER_NEW_TITLE, None);
        Self {
            shell,
            title,
            editing: false,
            read_only: false,
            draft,
            errors,
            stored: Stored::default(),
        }
    }

    /// The edit form of `draft.id`.
    pub(crate) fn edit(shell: Shell, draft: Draft, errors: FieldErrors) -> Self {
        let mut args = FluentArgs::new();
        args.set("name", draft.shown().to_owned());
        let title = tr(shell.locale(), keys::WEB_ROUTER_EDIT_TITLE, Some(&args));
        Self {
            shell,
            title,
            editing: true,
            read_only: false,
            draft,
            errors,
            stored: Stored::default(),
        }
    }

    /// Notes the credentials the edited profile has.
    #[must_use]
    pub(crate) fn with_stored(mut self, stored: Stored) -> Self {
        self.stored = stored;
        self
    }

    /// Shows the profile without controls.
    #[must_use]
    pub(crate) const fn read_only(mut self) -> Self {
        self.read_only = true;
        self
    }

    /// Where the form posts.
    fn action(&self) -> String {
        if self.editing {
            format!("/ui/routers/{}/edit", self.draft.id)
        } else {
            "/ui/routers/new".to_owned()
        }
    }

    /// Where Cancel leads.
    fn cancel(&self) -> String {
        if self.editing {
            format!("/ui/r/{}", self.draft.id)
        } else {
            "/ui/".to_owned()
        }
    }
}

localized!(FormPage);
