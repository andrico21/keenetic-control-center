//! The plan of one `router edit`.
//!
//! It holds the profile after the change, the credentials the command takes, the sealed
//! records it drops and the kinds that change. Planning reads no secret and writes
//! nothing, so a refused edit changes nothing.

use kcc_app::{
    credentials::CredentialKind,
    registry::ManagedRouterProfile,
    settings::{RouterAuth, RouterTls},
};
use kcc_i18n::keys;

use super::{
    args_router::{CredentialArgs, EditArgs},
    exit::Outcome,
    router_secrets::usage,
    routers::{parse_label, parse_url},
};

/// What one `router edit` does.
pub(super) struct Plan {
    /// The profile after the change; credential paths are pointed when sealing.
    profile: ManagedRouterProfile,
    /// Credential input options.
    inputs: CredentialArgs,
    /// Kinds whose new secret this command reads.
    given: Vec<CredentialKind>,
    /// Sealed records the profile no longer references.
    removed: Vec<CredentialKind>,
    /// Kinds that change (given or removed), for the audit entry.
    changed: Vec<CredentialKind>,
}

impl Plan {
    /// Kinds whose new secret this command reads.
    pub(super) fn given(&self) -> &[CredentialKind] {
        &self.given
    }

    /// The profile after the change, before its credential paths are pointed.
    pub(super) const fn profile(&self) -> &ManagedRouterProfile {
        &self.profile
    }

    /// Credential input options.
    pub(super) const fn inputs(&self) -> &CredentialArgs {
        &self.inputs
    }

    /// The profile after the change, the sealed records it no longer references and the
    /// kinds that change.
    pub(super) fn into_parts(
        self,
    ) -> (
        ManagedRouterProfile,
        Vec<CredentialKind>,
        Vec<CredentialKind>,
    ) {
        (self.profile, self.removed, self.changed)
    }
}

/// Plans the edit of `stored`.
///
/// A new URL, login or TLS pin needs the primary credential (password or token) in the
/// same command and drops the read-only credential unless it is given again. Switching
/// to token sign-in needs a token and drops the sealed password; switching away needs a
/// password and drops the sealed token.
///
/// # Errors
///
/// Returns a usage failure (exit 2) for a refused combination.
pub(super) fn plan(stored: &ManagedRouterProfile, args: EditArgs) -> Outcome<Plan> {
    let mut profile = stored.clone();
    if let Some(text) = args.url {
        profile.url = parse_url(&text)?;
    }
    if let Some(name) = args.login {
        profile.login = name;
    }
    match (args.clear_label, args.label) {
        (true, _) => profile.label = None,
        (false, Some(text)) => profile.label = parse_label(&text)?,
        (false, None) => {}
    }
    if !args.tags.is_empty() {
        profile.tags = args.tags;
    }
    if let Some(flag) = args.test_device {
        profile.test_device = flag;
    }
    if let Some(pin) = args.pin_sha256 {
        profile.tls = RouterTls::PinSha256(pin);
    }
    let inputs = args.credentials;
    let auth = inputs.auth.map_or(stored.auth, RouterAuth::from);
    let password = args.new_password;
    let token = args.edits.new_token || inputs.token_file.is_some();
    let read = args.edits.new_read_password
        || inputs.read_password_file.is_some()
        || inputs.read_login.is_some();
    let was_token = stored.password_file.is_none();
    let moved = profile.moves_endpoint(stored);
    let router = [("router", stored.id.as_str())];
    if token && auth != RouterAuth::Token {
        return Err(usage(keys::CLI_ROUTER_TOKEN_NEEDS_TOKEN_AUTH, &[]));
    }
    if password && auth == RouterAuth::Token {
        return Err(usage(
            keys::CLI_ROUTER_PASSWORD_NEEDS_PASSWORD_AUTH,
            &router,
        ));
    }
    if auth == RouterAuth::Token && !was_token && !token {
        return Err(usage(keys::CLI_ROUTER_SWITCH_NEEDS_TOKEN, &router));
    }
    if auth != RouterAuth::Token && was_token && !password {
        return Err(usage(keys::CLI_ROUTER_SWITCH_NEEDS_PASSWORD, &router));
    }
    if moved && !password && !token {
        return Err(usage(keys::CLI_ROUTER_CREDENTIAL_REQUIRED, &router));
    }
    if read && inputs.read_login.is_none() && stored.read_login.is_none() {
        return Err(usage(keys::CLI_ROUTER_READ_NEEDS_LOGIN, &[]));
    }
    profile.auth = auth;
    if let Some(login) = inputs.read_login.clone() {
        profile.read_login = Some(login);
    }
    let given = [
        (password, CredentialKind::Password),
        (token, CredentialKind::Token),
        (read, CredentialKind::ReadPassword),
    ]
    .into_iter()
    .filter_map(|(taken, kind)| taken.then_some(kind))
    .collect::<Vec<_>>();
    let mut removed = Vec::new();
    if args.edits.clear_read_login || (moved && !read) {
        profile.read_login = None;
        profile.read_password_file = None;
        if stored.read_password_file.is_some() {
            removed.push(CredentialKind::ReadPassword);
        }
    }
    if token && !was_token {
        removed.push(CredentialKind::Password);
    }
    if password && was_token {
        removed.push(CredentialKind::Token);
    }
    let changed = given.iter().chain(&removed).copied().collect();
    Ok(Plan {
        profile,
        inputs,
        given,
        removed,
        changed,
    })
}
