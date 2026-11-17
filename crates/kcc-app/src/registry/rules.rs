//! The one set of rules a router profile must satisfy, from `kcc.toml` or from state.

use super::ManagedRouterProfile;
use crate::settings::{RouterAuth, RouterProfile, RouterTls, is_valid_router_id};

/// The first rule a router profile breaks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProfileFault {
    /// The id is outside 1-32 characters of `[a-z0-9-]`.
    Id,
    /// The URL is not an `http` or `https` origin.
    Url,
    /// Not exactly one of `password_file` and `token_file` is set.
    CredentialSource,
    /// `token_file` is set but `auth` is not `token`.
    TokenFileNeedsTokenAuth,
    /// `auth = "token"` is set without `token_file`.
    TokenAuthNeedsTokenFile,
    /// `password_file` is set with an empty login.
    Login,
    /// Only one of `read_login` and `read_password_file` is set, or the login is empty.
    ReadPair,
    /// The TLS pin is not 64 hex digits.
    TlsPin,
}

impl ProfileFault {
    /// The profile key at fault, as `kcc.toml` names it.
    pub(crate) const fn field(self) -> &'static str {
        match self {
            Self::Id => "name",
            Self::Url => "url",
            Self::CredentialSource => "password_file",
            Self::TokenFileNeedsTokenAuth | Self::TokenAuthNeedsTokenFile => "auth",
            Self::Login => "login",
            Self::ReadPair => "read_login",
            Self::TlsPin => "tls.pin_sha256",
        }
    }

    /// Why the value is refused, naming the key.
    pub(crate) const fn reason(self) -> &'static str {
        match self {
            Self::Id => "id must be 1-32 characters of [a-z0-9-]",
            Self::Url => "url must be an http or https origin, without path, query or fragment",
            Self::CredentialSource => "set exactly one of password_file and token_file",
            Self::TokenFileNeedsTokenAuth => "token_file needs auth = \"token\"",
            Self::TokenAuthNeedsTokenFile => "auth = \"token\" needs token_file",
            Self::Login => "login is required with password_file",
            Self::ReadPair => "set both non-empty read_login and read_password_file, or neither",
            Self::TlsPin => "tls pin_sha256 must be 64 hex digits",
        }
    }
}

/// Checks `profile` against every profile rule, in field order.
///
/// # Errors
/// The first [`ProfileFault`] found.
pub(crate) fn check(profile: &ManagedRouterProfile) -> Result<(), ProfileFault> {
    if !is_valid_router_id(&profile.id) {
        return Err(ProfileFault::Id);
    }
    let url = &profile.url;
    if !matches!(url.scheme(), "http" | "https")
        || url.host().is_none()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(ProfileFault::Url);
    }
    match (&profile.password_file, &profile.token_file) {
        (Some(_), None) if profile.auth == RouterAuth::Token => {
            return Err(ProfileFault::TokenAuthNeedsTokenFile);
        }
        (Some(_), None) if profile.login.is_empty() => return Err(ProfileFault::Login),
        (None, Some(_)) if profile.auth != RouterAuth::Token => {
            return Err(ProfileFault::TokenFileNeedsTokenAuth);
        }
        (Some(_), None) | (None, Some(_)) => {}
        (Some(_), Some(_)) | (None, None) => return Err(ProfileFault::CredentialSource),
    }
    match (&profile.read_login, &profile.read_password_file) {
        (None, None) => {}
        (Some(login), Some(_)) if !login.is_empty() => {}
        (Some(_) | None, Some(_)) | (Some(_), None) => return Err(ProfileFault::ReadPair),
    }
    match &profile.tls {
        RouterTls::PinSha256(pin)
            if !(pin.len() == 64 && pin.bytes().all(|byte| byte.is_ascii_hexdigit())) =>
        {
            Err(ProfileFault::TlsPin)
        }
        RouterTls::Verify | RouterTls::PinSha256(_) => Ok(()),
    }
}

/// Converts a config-defined profile into the common registry representation.
pub(crate) fn from_config(profile: &RouterProfile) -> ManagedRouterProfile {
    let auth = match (profile.auth, &profile.token_file) {
        (RouterAuth::Auto, Some(_)) => RouterAuth::Token,
        (auth, _) => auth,
    };
    ManagedRouterProfile {
        id: profile.name.clone(),
        url: profile.url.clone(),
        login: profile.login.clone().unwrap_or_default(),
        password_file: profile.password_file.clone(),
        auth,
        token_file: profile.token_file.clone(),
        read_login: profile.read_login.clone(),
        read_password_file: profile.read_password_file.clone(),
        tls: profile.tls.clone(),
        test_device: profile.test_device,
        tags: profile.tags.clone(),
    }
}
