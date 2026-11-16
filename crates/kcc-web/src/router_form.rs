//! The router profile form: submitted fields and their validation.

pub(crate) mod address;
pub(crate) mod page;
pub(crate) mod plan;

use kcc_app::{
    registry::ManagedRouterProfile,
    settings::{RouterAuth, RouterTls},
};
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use secrecy::SecretString;
use serde::Deserialize;
use url::Url;

use self::address::origin;
use crate::page_kit::secret::write_only;

/// The submitted router form. Every secret moves into a [`SecretString`] in
/// [`RouterForm::parse`] before any other use and is never echoed back.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RouterForm {
    /// New profile id (add form).
    #[serde(default)]
    id: String,
    /// Edited profile id (edit form, hidden).
    #[serde(default)]
    router: String,
    /// Router address.
    #[serde(default)]
    url: String,
    /// Login.
    #[serde(default)]
    login: String,
    /// Password; empty keeps the stored one when editing.
    #[serde(default)]
    password: String,
    /// Sign-in mode: `auto` (or empty), `ndw2`, `ndw4`, `token` or `digest`.
    #[serde(default)]
    auth: String,
    /// API token of mode `token`; empty keeps the stored one when editing.
    #[serde(default)]
    token: String,
    /// Read-only polling login.
    #[serde(default)]
    read_login: String,
    /// Read-only polling password; empty keeps the stored one.
    #[serde(default)]
    read_password: String,
    /// Present when "remove read-only login" is checked.
    #[serde(default)]
    clear_read: Option<String>,
    /// `verify` or `pin`.
    #[serde(default)]
    tls: String,
    /// Certificate SHA-256 for `pin`.
    #[serde(default)]
    tls_pin: String,
    /// Comma-separated tags.
    #[serde(default)]
    tags: String,
    /// Present when the test-device box is checked.
    #[serde(default)]
    test_device: Option<String>,
}

/// The sign-in modes the form offers, by their form value.
const MODES: [(&str, RouterAuth); 5] = [
    ("auto", RouterAuth::Auto),
    ("ndw2", RouterAuth::Ndw2),
    ("ndw4", RouterAuth::Ndw4),
    ("token", RouterAuth::Token),
    ("digest", RouterAuth::Digest),
];

/// What the form shows again: every field but the secrets.
#[derive(Debug, Clone, Default)]
pub(crate) struct Draft {
    /// Profile id.
    id: String,
    /// Router address.
    url: String,
    /// Login.
    login: String,
    /// Form value of the sign-in mode.
    auth: &'static str,
    /// Read-only polling login.
    read_login: String,
    /// Whether a certificate is pinned.
    pinned: bool,
    /// Certificate SHA-256.
    pin: String,
    /// Comma-separated tags.
    tags: String,
    /// Test-device flag.
    test_device: bool,
}

impl Draft {
    /// The stored values of `profile`.
    pub(crate) fn from_profile(profile: &ManagedRouterProfile) -> Self {
        let (pinned, pin) = match &profile.tls {
            RouterTls::PinSha256(pin) => (true, pin.clone()),
            RouterTls::Verify | _ => (false, String::new()),
        };
        Self {
            id: profile.id.clone(),
            url: profile.url.as_str().trim_end_matches('/').to_owned(),
            login: profile.login.clone(),
            auth: MODES
                .iter()
                .find(|(_, mode)| *mode == profile.auth)
                .map_or("auto", |(value, _)| value),
            read_login: profile.read_login.clone().unwrap_or_default(),
            pinned,
            pin,
            tags: profile.tags.join(", "),
            test_device: profile.test_device,
        }
    }

    /// Profile id.
    pub(crate) fn id(&self) -> &str {
        &self.id
    }

    /// The same values for the profile `id`.
    #[must_use]
    pub(crate) fn with_id(mut self, id: String) -> Self {
        self.id = id;
        self
    }
}

/// One localized message per invalid field; empty strings mean valid.
#[derive(Debug, Clone, Default)]
pub(crate) struct FieldErrors {
    /// Profile id.
    id: String,
    /// Address, including outbound-policy refusals.
    url: String,
    /// Login.
    login: String,
    /// Sign-in mode.
    auth: String,
    /// Password.
    password: String,
    /// API token.
    token: String,
    /// Certificate pin.
    pin: String,
    /// Read-only polling login.
    read_login: String,
    /// Read-only polling password.
    read_password: String,
}

impl FieldErrors {
    /// Whether any field is invalid.
    pub(crate) fn any(&self) -> bool {
        !self.first().is_empty()
    }

    /// Marks the id as invalid with `message`.
    pub(crate) fn set_id(&mut self, message: String) {
        self.id = message;
    }

    /// Marks the address as invalid with `message`.
    pub(crate) fn set_url(&mut self, message: String) {
        self.url = message;
    }

    /// The first field message, in form order.
    pub(crate) fn first(&self) -> &str {
        [
            &self.id,
            &self.url,
            &self.login,
            &self.auth,
            &self.password,
            &self.token,
            &self.pin,
            &self.read_login,
            &self.read_password,
        ]
        .into_iter()
        .find(|message| !message.is_empty())
        .map_or("", String::as_str)
    }
}

/// The secrets typed into a form; an empty field is `None`. The password of mode `token`
/// and the token of a password mode are hidden fields and are dropped.
#[derive(Default)]
pub(crate) struct Typed {
    /// Management password.
    password: Option<SecretString>,
    /// API token.
    token: Option<SecretString>,
    /// Read-only polling password.
    read: Option<SecretString>,
}

impl Typed {
    /// The typed primary secret: the token in mode `token`, otherwise the password.
    pub(crate) fn into_primary(self) -> Option<SecretString> {
        self.token.or(self.password)
    }
}

/// The valid fields of a form.
pub(crate) struct Parsed {
    /// Router origin.
    url: Url,
    /// Login.
    login: String,
    /// Sign-in mode.
    auth: RouterAuth,
    /// Read-only polling login.
    read_login: String,
    /// Whether "remove read-only login" is checked.
    clear_read: bool,
    /// TLS policy.
    tls: RouterTls,
    /// Tags.
    tags: Vec<String>,
    /// Test-device flag.
    test_device: bool,
}

impl Parsed {
    /// Router origin.
    pub(crate) const fn url(&self) -> &Url {
        &self.url
    }

    /// Sign-in mode.
    pub(crate) const fn auth(&self) -> RouterAuth {
        self.auth
    }

    /// Whether applying these fields would move the profile's endpoint (the rule the
    /// CLI applies too), which needs the primary credential again.
    pub(crate) fn moves_credential(&self, profile: &ManagedRouterProfile) -> bool {
        let mut moved = profile.clone();
        moved.url.clone_from(&self.url);
        moved.login.clone_from(&self.login);
        moved.tls.clone_from(&self.tls);
        moved.moves_endpoint(profile)
    }

    /// Copies the parsed fields into `profile`, keeping its id, sign-in mode and
    /// credentials ([`plan::Plan`] changes those).
    pub(crate) fn apply(self, profile: &mut ManagedRouterProfile) {
        profile.url = self.url;
        profile.login = self.login;
        profile.tls = self.tls;
        profile.tags = self.tags;
        profile.test_device = self.test_device;
    }
}

impl RouterForm {
    /// The edited router id, empty on the add form.
    pub(crate) fn router(&self) -> &str {
        &self.router
    }

    /// The new router id, empty on the edit form.
    pub(crate) fn id(&self) -> &str {
        self.id.trim()
    }

    /// Validates the fields; returns the draft to show again, the typed secrets, and the
    /// parsed fields or the field errors. `primary_required` asks for the password, or the
    /// token in mode `token`.
    pub(crate) fn parse(
        self,
        locale: Locale,
        primary_required: bool,
    ) -> (Draft, Typed, Result<Parsed, FieldErrors>) {
        let message = |key| tr(locale, key, None);
        let mut errors = FieldErrors::default();
        let mut draft = Draft {
            id: self.id.trim().to_owned(),
            url: self.url.trim().to_owned(),
            login: self.login.trim().to_owned(),
            auth: "auto",
            read_login: self.read_login.trim().to_owned(),
            pinned: self.tls == "pin",
            pin: self.tls_pin.trim().to_ascii_lowercase(),
            tags: self.tags.trim().to_owned(),
            test_device: self.test_device.is_some(),
        };
        let wanted = if self.auth.is_empty() {
            "auto"
        } else {
            self.auth.as_str()
        };
        let mode = MODES.iter().find(|(value, _)| *value == wanted);
        let auth = mode.map_or(RouterAuth::Auto, |(_, auth)| *auth);
        draft.auth = mode.map_or("auto", |(value, _)| value);
        if mode.is_none() {
            errors.auth = message(keys::WEB_ROUTER_ERROR_AUTH);
        }
        let token_mode = auth == RouterAuth::Token;
        let typed = Typed {
            password: write_only(self.password).filter(|_| !token_mode),
            token: write_only(self.token).filter(|_| token_mode),
            read: write_only(self.read_password),
        };
        let url = origin(&draft.url);
        if url.is_none() {
            errors.url = message(keys::WEB_ROUTER_ERROR_URL);
        }
        if draft.login.is_empty() {
            errors.login = message(keys::WEB_ROUTER_ERROR_LOGIN);
        }
        match (primary_required, token_mode) {
            (true, true) if typed.token.is_none() => {
                errors.token = message(keys::WEB_ROUTER_ERROR_TOKEN);
            }
            (true, false) if typed.password.is_none() => {
                errors.password = message(keys::WEB_ROUTER_ERROR_PASSWORD);
            }
            (true | false, _) => {}
        }
        let tls = if draft.pinned {
            let valid =
                draft.pin.len() == 64 && draft.pin.bytes().all(|byte| byte.is_ascii_hexdigit());
            if !valid {
                errors.pin = message(keys::WEB_ROUTER_ERROR_PIN);
            }
            RouterTls::PinSha256(draft.pin.clone())
        } else {
            RouterTls::Verify
        };
        let parsed = match url {
            Some(target) if !errors.any() => Ok(Parsed {
                url: target,
                login: draft.login.clone(),
                auth,
                read_login: draft.read_login.clone(),
                clear_read: self.clear_read.is_some(),
                tls,
                tags: draft
                    .tags
                    .split(',')
                    .map(str::trim)
                    .filter(|tag| !tag.is_empty())
                    .map(str::to_owned)
                    .collect(),
                test_device: draft.test_device,
            }),
            Some(_) | None => Err(errors),
        };
        (draft, typed, parsed)
    }
}
