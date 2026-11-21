//! The closed Entware command set: the only way this crate builds an exec string.
//!
//! Each variant renders one `const` template. Every rendered string starts with a fixed
//! `PATH` prologue, and every argument is a grammar-checked value from
//! [`grammar`](crate::grammar) inside POSIX single quotes (`'` becomes `'\''`).

use crate::grammar::{PackageName, PublicKeyLine, RouterId, ServiceAction, ServiceName};

/// The `PATH` every command runs with.
const PATH: &str = "/opt/bin:/opt/sbin:/bin:/sbin:/usr/bin:/usr/sbin";

/// dropbear's configuration directory, which holds `authorized_keys`.
const DROPBEAR: &str = "/opt/etc/dropbear";

/// Directory of the init scripts.
const INIT_D: &str = "/opt/etc/init.d/";

/// The prologue of every command; `@PATH@` is [`PATH`].
const PROLOGUE: &str = "PATH=@PATH@; export PATH; ";

/// `opkg list-installed`.
const LIST_INSTALLED: &str = "/opt/bin/opkg list-installed";

/// `opkg list-upgradable`.
const LIST_UPGRADABLE: &str = "/opt/bin/opkg list-upgradable";

/// `opkg update`.
const UPDATE: &str = "/opt/bin/opkg update";

/// `opkg install`; `@ARG@` is the quoted package name.
const INSTALL: &str = "/opt/bin/opkg install @ARG@";

/// `opkg remove`; `@ARG@` is the quoted package name.
const REMOVE: &str = "/opt/bin/opkg remove @ARG@";

/// `opkg upgrade`; `@ARG@` is the quoted package name.
const UPGRADE: &str = "/opt/bin/opkg upgrade @ARG@";

/// Prints the init script names, one per line; exits 0 for an empty or unexpanded glob.
const LIST_SERVICES: &str =
    r#"for f in /opt/etc/init.d/S*; do if [ -f "$f" ]; then printf '%s\n' "${f##*/}"; fi; done"#;

/// One init script action; `@ARG@` is the quoted script path, `@ACTION@` the bare word.
const SERVICE: &str = "@ARG@ @ACTION@";

/// Replaces the router's `kcc:<id>` line of `authorized_keys` (`@FILE@`) with `@ENTRY@`.
///
/// Every other line is kept. A `grep` failure other than "no lines" (exit above 1)
/// fails the group, so the file is never replaced, and the tail removes the temp file.
const APPEND_KEY: &str = r"umask 077 && mkdir -p @DIR@ && touch @FILE@ && { grep -v @PATTERN@ @FILE@; [ $? -le 1 ] && printf '%s\n' @ENTRY@; } > @FILE@.kcc && mv @FILE@.kcc @FILE@ && chmod 700 @DIR@ && chmod 600 @FILE@ || { rm -f @FILE@.kcc; false; }";

/// Removes the router's `kcc:<id>` line of `authorized_keys` (`@FILE@`), keeping every
/// other line, with the same failure handling as [`APPEND_KEY`].
const REMOVE_KEY: &str = "umask 077 && touch @FILE@ && { grep -v @PATTERN@ @FILE@; [ $? -le 1 ]; } > @FILE@.kcc && mv @FILE@.kcc @FILE@ && chmod 600 @FILE@ || { rm -f @FILE@.kcc; false; }";

/// One command kcc may run on Entware.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
#[expect(
    clippy::module_name_repetitions,
    reason = "the command set is named EntwareCommand across the crates that use it"
)]
pub enum EntwareCommand {
    /// `opkg list-installed`.
    ListInstalled,
    /// `opkg list-upgradable`.
    ListUpgradable,
    /// `opkg update`.
    Update,
    /// `opkg install <package>`.
    Install(PackageName),
    /// `opkg remove <package>`.
    Remove(PackageName),
    /// `opkg upgrade <package>`.
    Upgrade(PackageName),
    /// Lists `/opt/etc/init.d/S*`.
    ListServices,
    /// `/opt/etc/init.d/<service> <action>`.
    Service(ServiceName, ServiceAction),
    /// Installs `line` as the router's only `kcc:<router_id>` line of dropbear's
    /// `authorized_keys`, creating the file (mode 600) and directory (mode 700) as needed.
    AppendKey {
        /// The public key, `ssh-ed25519 <base64>`.
        line: PublicKeyLine,
        /// The router whose line it is.
        router_id: RouterId,
    },
    /// Removes the router's `kcc:<router_id>` line of dropbear's `authorized_keys`.
    RemoveKey {
        /// The router whose line it is.
        router_id: RouterId,
    },
}

impl EntwareCommand {
    /// Whether the command changes the router; it then runs under the mutation timeout.
    #[inline]
    #[must_use]
    pub const fn is_mutation(&self) -> bool {
        match self {
            Self::ListInstalled | Self::ListUpgradable | Self::ListServices => false,
            Self::Service(_, action) => !matches!(action, ServiceAction::Check),
            Self::Update
            | Self::Install(_)
            | Self::Remove(_)
            | Self::Upgrade(_)
            | Self::AppendKey {
                line: _,
                router_id: _,
            }
            | Self::RemoveKey { router_id: _ } => true,
        }
    }

    /// The exec string sent to the router.
    pub(crate) fn render(&self) -> String {
        self.render_with(DROPBEAR, PATH)
    }

    /// The exec string with dropbear's directory `dropbear` and `PATH` value `path`.
    fn render_with(&self, dropbear: &str, path: &str) -> String {
        let file = format!("{dropbear}/authorized_keys");
        let body = match self {
            Self::ListInstalled => LIST_INSTALLED.to_owned(),
            Self::ListUpgradable => LIST_UPGRADABLE.to_owned(),
            Self::Update => UPDATE.to_owned(),
            Self::Install(package) => fill(INSTALL, &[("ARG", quote(package.as_str()))]),
            Self::Remove(package) => fill(REMOVE, &[("ARG", quote(package.as_str()))]),
            Self::Upgrade(package) => fill(UPGRADE, &[("ARG", quote(package.as_str()))]),
            Self::ListServices => LIST_SERVICES.to_owned(),
            Self::Service(service, action) => fill(
                SERVICE,
                &[
                    ("ARG", quote(&format!("{INIT_D}{}", service.as_str()))),
                    ("ACTION", action.as_str().to_owned()),
                ],
            ),
            Self::AppendKey { line, router_id } => fill(
                APPEND_KEY,
                &[
                    ("DIR", dropbear.to_owned()),
                    ("FILE", file),
                    ("PATTERN", pattern(router_id)),
                    (
                        "ENTRY",
                        quote(&format!("{} kcc:{}", line.as_str(), router_id.as_str())),
                    ),
                ],
            ),
            Self::RemoveKey { router_id } => fill(
                REMOVE_KEY,
                &[("FILE", file), ("PATTERN", pattern(router_id))],
            ),
        };
        format!("{}{body}", fill(PROLOGUE, &[("PATH", path.to_owned())]))
    }
}

/// The quoted `grep` pattern of the router's `authorized_keys` line.
fn pattern(router_id: &RouterId) -> String {
    quote(&format!(" kcc:{}$", router_id.as_str()))
}

/// `text` as one POSIX single-quoted shell word.
fn quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', r"'\''"))
}

/// Replaces each `@NAME@` of `template` with the value named `NAME`, in one pass: a
/// value is never scanned for placeholders. An unknown name renders empty.
fn fill(template: &str, values: &[(&str, String)]) -> String {
    let mut rendered = String::with_capacity(template.len());
    let mut placeholder = false;
    for part in template.split('@') {
        if placeholder {
            let value = values
                .iter()
                .find_map(|(name, value)| (*name == part).then_some(value.as_str()));
            rendered.push_str(value.unwrap_or_default());
        } else {
            rendered.push_str(part);
        }
        placeholder = !placeholder;
    }
    rendered
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests;

#[cfg(all(test, unix))]
#[expect(
    clippy::tests_outside_test_module,
    reason = "clippy does not read cfg(all(test, unix)) as a test module"
)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod script_tests;
