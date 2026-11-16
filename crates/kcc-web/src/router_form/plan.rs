//! What one router form submit does to the stored credentials: the secrets it seals, the
//! sealed records it drops and the kinds that change.
//!
//! The rule is the CLI's: a new address, login or TLS pin needs the primary credential
//! (password, or the token in mode `token`) again and drops the read-only login unless it
//! is entered again; switching to mode `token` needs a token and drops the sealed password,
//! switching away needs a password and drops the sealed token. Planning writes nothing,
//! so a refused submit changes nothing.

use kcc_app::{
    credentials::{CredentialError, CredentialKind, CredentialStore},
    registry::ManagedRouterProfile,
    settings::RouterAuth,
};
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use secrecy::SecretString;

use super::{FieldErrors, Parsed, Typed};

/// A field a refused submit has to fill in.
#[derive(Clone, Copy)]
enum Missing {
    /// The management password.
    Password,
    /// The API token.
    Token,
    /// The read-only login, for a typed read-only password.
    ReadLogin,
    /// The read-only password, for a new read-only login.
    ReadPassword,
}

/// The fields a refused submit has to fill in.
pub(crate) struct Refusal(Vec<Missing>);

impl Refusal {
    /// Marks every missing field of `errors` in `locale`.
    pub(crate) fn mark(&self, errors: &mut FieldErrors, locale: Locale) {
        for missing in &self.0 {
            let (field, key) = match missing {
                Missing::Password => (&mut errors.password, keys::WEB_ROUTER_ERROR_PASSWORD),
                Missing::Token => (&mut errors.token, keys::WEB_ROUTER_ERROR_TOKEN),
                Missing::ReadLogin => (&mut errors.read_login, keys::WEB_ROUTER_ERROR_READ_LOGIN),
                Missing::ReadPassword => (
                    &mut errors.read_password,
                    keys::WEB_ROUTER_ERROR_READ_PASSWORD,
                ),
            };
            *field = tr(locale, key, None);
        }
    }
}

/// What happens to the read-only polling login.
enum Reader {
    /// It stays as stored.
    Keep,
    /// It becomes this login with a newly typed password.
    Set(String),
    /// It is removed.
    Remove,
}

/// The credential changes of one valid submit.
pub(crate) struct Plan {
    /// Sign-in mode after the change.
    auth: RouterAuth,
    /// The read-only polling login after the change.
    reader: Reader,
    /// Secrets to seal, each with its kind.
    secrets: Vec<(CredentialKind, SecretString)>,
    /// Sealed records the profile no longer references.
    removed: Vec<CredentialKind>,
}

impl Plan {
    /// Plans the credentials of `fields` for a new profile (`stored` is `None`) or for the
    /// edit of `stored`.
    ///
    /// # Errors
    ///
    /// Returns the fields a refused submit has to fill in.
    pub(crate) fn new(
        stored: Option<&ManagedRouterProfile>,
        fields: &Parsed,
        typed: Typed,
    ) -> Result<Self, Refusal> {
        let mut missing = Vec::new();
        let token_mode = fields.auth == RouterAuth::Token;
        let was_token = stored.is_some_and(|profile| profile.password_file.is_none());
        let moved = stored.is_none_or(|profile| fields.moves_credential(profile));
        let (kind, primary) = if token_mode {
            (CredentialKind::Token, typed.token)
        } else {
            (CredentialKind::Password, typed.password)
        };
        if primary.is_none() && (moved || token_mode != was_token) {
            missing.push(if token_mode {
                Missing::Token
            } else {
                Missing::Password
            });
        }
        let stored_reader = stored.and_then(|profile| profile.read_login.as_deref());
        let login = fields.read_login.as_str();
        let mut reader = match (fields.clear_read, &typed.read) {
            (true, _) => Reader::Remove,
            (false, Some(_)) if login.is_empty() => {
                missing.push(Missing::ReadLogin);
                Reader::Keep
            }
            (false, Some(_)) => Reader::Set(login.to_owned()),
            (false, None) if login.is_empty() || stored_reader == Some(login) => Reader::Keep,
            (false, None) => {
                missing.push(Missing::ReadPassword);
                Reader::Keep
            }
        };
        if moved && matches!(reader, Reader::Keep) {
            reader = Reader::Remove;
        }
        if !missing.is_empty() {
            return Err(Refusal(missing));
        }
        let mut secrets = primary
            .map(|secret| (kind, secret))
            .into_iter()
            .collect::<Vec<_>>();
        let mut removed = Vec::new();
        if let (Reader::Set(_), Some(secret)) = (&reader, typed.read) {
            secrets.push((CredentialKind::ReadPassword, secret));
        }
        if let Some(profile) = stored {
            if matches!(reader, Reader::Remove) && profile.read_password_file.is_some() {
                removed.push(CredentialKind::ReadPassword);
            }
            match (secrets.first(), was_token) {
                (Some((CredentialKind::Token, _)), false) => removed.push(CredentialKind::Password),
                (Some((CredentialKind::Password, _)), true) => removed.push(CredentialKind::Token),
                (Some(_) | None, _) => {}
            }
        }
        Ok(Self {
            auth: fields.auth,
            reader,
            secrets,
            removed,
        })
    }

    /// The kinds that change (sealed or removed), in audit order.
    pub(crate) fn changed(&self) -> Vec<CredentialKind> {
        CredentialKind::ALL
            .into_iter()
            .filter(|kind| {
                self.removed.contains(kind) || self.secrets.iter().any(|(given, _)| given == kind)
            })
            .collect()
    }

    /// Sets the sign-in mode and the read-only login of `profile` and points it at the
    /// sealed record of every secret; a primary credential of one kind replaces the other.
    ///
    /// # Errors
    ///
    /// Returns a credential path failure.
    pub(crate) fn point(
        &self,
        store: &CredentialStore,
        profile: &mut ManagedRouterProfile,
    ) -> Result<(), CredentialError> {
        profile.auth = self.auth;
        match &self.reader {
            Reader::Keep => {}
            Reader::Set(login) => profile.read_login = Some(login.clone()),
            Reader::Remove => {
                profile.read_login = None;
                profile.read_password_file = None;
            }
        }
        for (kind, _) in &self.secrets {
            let sealed = Some(store.sealed_path(&profile.id, *kind)?);
            match kind {
                CredentialKind::Token => {
                    profile.token_file = sealed;
                    profile.password_file = None;
                }
                CredentialKind::ReadPassword => profile.read_password_file = sealed,
                CredentialKind::Password | _ => {
                    profile.password_file = sealed;
                    profile.token_file = None;
                }
            }
        }
        Ok(())
    }

    /// The typed secrets, each with its kind.
    pub(crate) fn secrets(&self) -> &[(CredentialKind, SecretString)] {
        &self.secrets
    }

    /// Seals every typed secret of router `id`.
    ///
    /// # Errors
    ///
    /// Returns the first storage or encryption failure.
    pub(crate) fn seal(&self, store: &CredentialStore, id: &str) -> Result<(), CredentialError> {
        self.secrets
            .iter()
            .try_for_each(|(kind, secret)| store.store(id, *kind, secret))
    }

    /// Removes the sealed records router `id` no longer references.
    ///
    /// # Errors
    ///
    /// Returns the first storage failure.
    pub(crate) fn remove(&self, store: &CredentialStore, id: &str) -> Result<(), CredentialError> {
        self.removed
            .iter()
            .try_for_each(|kind| store.remove_kind(id, *kind))
    }
}
