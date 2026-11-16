//! The associated data binding every value sealed with the master key to its record type
//! and owner. Every encoding is built here and nowhere else.
//!
//! A binding is `<tag>:<owner>`, plus a fixed `:<part>` for record types that seal more
//! than one part. The tags (`router`, `account`, `backup`, `migration`, `preset-run`,
//! `preset`) hold no `:`, so the bytes before the first `:` name the record type and two
//! record types never share a binding. Within one type the owner is recovered too:
//!
//! - `router:<id>`, `router:<id>:token`, `router:<id>:read`: a checked router id holds
//!   no `:`, so whatever follows the id names the kind.
//! - `account:<username>`: the username is all the rest.
//! - `backup:<router>:<name>`: the router is a checked backup component with no `:`, so
//!   the next `:` ends it.
//! - `migration:<id>:source`, `migration:<id>:passwords`, `preset-run:<id>:preset`: the
//!   last word is fixed per part and the id is everything before it.
//! - `preset:<id>`: the id is all the rest.
//!
//! Two bindings are therefore equal only for the same record, and a ciphertext moved to
//! any other record fails to open.

use crate::credentials::{CredentialKind, router_id::RouterId};

/// The associated data of one sealed record. It is not secret.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Binding(String);

impl Binding {
    /// A router credential of `kind`: `router:<id>`, `router:<id>:token` or
    /// `router:<id>:read`.
    pub(crate) fn router(router: RouterId<'_>, kind: CredentialKind) -> Self {
        let id = router.as_str();
        Self(match kind {
            CredentialKind::Password => format!("router:{id}"),
            CredentialKind::Token => format!("router:{id}:token"),
            CredentialKind::ReadPassword => format!("router:{id}:read"),
        })
    }

    /// A UI account's password hash: `account:<username>`.
    #[inline]
    #[must_use]
    pub fn account(username: &str) -> Self {
        Self(format!("account:{username}"))
    }

    /// A configuration backup: `backup:<router>:<name>`, for a `router` that passed the
    /// backup component check.
    pub(crate) fn backup(router: &str, name: &str) -> Self {
        Self(format!("backup:{router}:{name}"))
    }

    /// The source configuration of migration `id`: `migration:<id>:source`.
    #[inline]
    #[must_use]
    pub fn migration_source(id: &str) -> Self {
        Self(format!("migration:{id}:source"))
    }

    /// The typed passwords of migration `id`: `migration:<id>:passwords`.
    #[inline]
    #[must_use]
    pub fn migration_passwords(id: &str) -> Self {
        Self(format!("migration:{id}:passwords"))
    }

    /// The preset applied by preset run `id`: `preset-run:<id>:preset`.
    #[inline]
    #[must_use]
    pub fn preset_run(id: &str) -> Self {
        Self(format!("preset-run:{id}:preset"))
    }

    /// The stored preset `id`: `preset:<id>`.
    #[inline]
    #[must_use]
    pub fn preset(id: &str) -> Self {
        Self(format!("preset:{id}"))
    }

    /// The bytes the cipher authenticates.
    pub(super) const fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::Binding;
    use crate::credentials::{CredentialError, CredentialKind, router_id::RouterId};

    /// SEC2-18: one owner name is bound under every record type's own tag, in the bytes
    /// the stored records were sealed with.
    #[test]
    #[expect(
        clippy::missing_errors_doc,
        clippy::missing_panics_doc,
        clippy::panic_in_result_fn,
        reason = "the assertions define the stored bindings"
    )]
    fn each_record_type_binds_its_owner_under_its_own_tag() -> Result<(), CredentialError> {
        let router = RouterId::parse("home")?;
        let bindings = [
            (
                Binding::router(router, CredentialKind::Password),
                "router:home",
            ),
            (
                Binding::router(router, CredentialKind::Token),
                "router:home:token",
            ),
            (
                Binding::router(router, CredentialKind::ReadPassword),
                "router:home:read",
            ),
            (Binding::account("home"), "account:home"),
            (Binding::backup("home", "1-a.txt"), "backup:home:1-a.txt"),
            (Binding::migration_source("home"), "migration:home:source"),
            (
                Binding::migration_passwords("home"),
                "migration:home:passwords",
            ),
            (Binding::preset_run("home"), "preset-run:home:preset"),
            (Binding::preset("home"), "preset:home"),
        ];

        for (binding, expected) in &bindings {
            assert_eq!(binding.as_bytes(), expected.as_bytes());
        }
        Ok(())
    }
}
