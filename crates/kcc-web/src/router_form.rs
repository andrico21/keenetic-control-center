//! The router profile form: submitted fields, their validation, and the form page.

use askama::Template;
use fluent_bundle::FluentArgs;
use kcc_app::{registry::ManagedRouterProfile, settings::RouterTls};
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use secrecy::SecretString;
use serde::Deserialize;
use url::Url;

use crate::page::{Localize, Shell};

/// The submitted router form. The password moves into a [`SecretString`] in
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

/// What the form shows again: every field but the password.
#[derive(Debug, Clone, Default)]
pub(crate) struct Draft {
    /// Profile id.
    id: String,
    /// Router address.
    url: String,
    /// Login.
    login: String,
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
    /// Password.
    password: String,
    /// Certificate pin.
    pin: String,
}

impl FieldErrors {
    /// Whether any field is invalid.
    pub(crate) const fn any(&self) -> bool {
        !(self.id.is_empty()
            && self.url.is_empty()
            && self.login.is_empty()
            && self.password.is_empty()
            && self.pin.is_empty())
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
        [&self.id, &self.url, &self.login, &self.password, &self.pin]
            .into_iter()
            .find(|message| !message.is_empty())
            .map_or("", String::as_str)
    }
}

/// The valid fields of a form.
pub(crate) struct Parsed {
    /// Router origin.
    url: Url,
    /// Login.
    login: String,
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

    /// Copies the parsed fields into `profile`, keeping its id, password file and
    /// read-only poll credentials.
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

    /// Validates the fields; returns the draft to show again, the password if one was
    /// typed, and the parsed fields or the field errors.
    pub(crate) fn parse(
        self,
        locale: Locale,
        password_required: bool,
    ) -> (Draft, Option<SecretString>, Result<Parsed, FieldErrors>) {
        let message = |key| tr(locale, key, None);
        let mut errors = FieldErrors::default();
        let draft = Draft {
            id: self.id.trim().to_owned(),
            url: self.url.trim().to_owned(),
            login: self.login.trim().to_owned(),
            pinned: self.tls == "pin",
            pin: self.tls_pin.trim().to_ascii_lowercase(),
            tags: self.tags.trim().to_owned(),
            test_device: self.test_device.is_some(),
        };
        let password = (!self.password.is_empty()).then(|| SecretString::from(self.password));
        let url = origin(&draft.url);
        if url.is_none() {
            errors.url = message(keys::WEB_ROUTER_ERROR_URL);
        }
        if draft.login.is_empty() {
            errors.login = message(keys::WEB_ROUTER_ERROR_LOGIN);
        }
        if password_required && password.is_none() {
            errors.password = message(keys::WEB_ROUTER_ERROR_PASSWORD);
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
        (draft, password, parsed)
    }
}

/// An `http`/`https` origin with a host and no path, query or fragment.
fn origin(text: &str) -> Option<Url> {
    let url = Url::parse(text).ok()?;
    let valid = matches!(url.scheme(), "http" | "https")
        && url.host().is_some()
        && url.path() == "/"
        && url.query().is_none()
        && url.fragment().is_none()
        && url.username().is_empty()
        && url.password().is_none();
    valid.then_some(url)
}

/// Whether `id` is a registry slug: 1 to 32 of `a-z`, `0-9` and `-`.
pub(crate) fn is_slug(id: &str) -> bool {
    (1..=32).contains(&id.len())
        && id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
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
        }
    }

    /// The edit form of `draft.id`; `read_only` for a `kcc.toml` profile.
    pub(crate) fn edit(shell: Shell, draft: Draft, errors: FieldErrors) -> Self {
        let mut args = FluentArgs::new();
        args.set("name", draft.id.clone());
        let title = tr(shell.locale(), keys::WEB_ROUTER_EDIT_TITLE, Some(&args));
        Self {
            shell,
            title,
            editing: true,
            read_only: false,
            draft,
            errors,
        }
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

impl Localize for FormPage {
    fn shell(&self) -> &Shell {
        &self.shell
    }
}
