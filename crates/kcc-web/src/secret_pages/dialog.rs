//! The write-only secret dialog and what its two fields ask for.
//!
//! The dialog never has a value to show: its secret fields always render empty, and the
//! typed value is read once from the form body, compared with its repetition and moved
//! into a `SecretString`.

use core::mem;

use askama::Template;
use axum::response::Response;
use fluent_bundle::FluentArgs;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};
use secrecy::{ExposeSecret as _, SecretString, zeroize::Zeroize as _};

use crate::{
    errors,
    page::{Localize as _, Shell},
    page_kit::{
        confirm::FAIL_SAFE_MINUTES,
        context::fragment_shell,
        respond::{self, Answer},
        secret::write_only,
    },
};

/// The form field of the new value.
const SECRET: &str = "secret";

/// The form field repeating it.
const REPEAT: &str = "secret_again";

/// What the dialog's two secret fields ask for.
pub(crate) enum Entry {
    /// Both empty: the stored value stays and nothing is sent.
    Keep,
    /// The two entries differ.
    Mismatch,
    /// A new value, typed twice.
    New(SecretString),
}

/// Takes the secret fields out of `pairs`, leaving every other field.
pub(crate) fn entry(pairs: &mut Vec<(String, String)>) -> Entry {
    let mut typed = take(pairs, SECRET);
    let mut repeated = take(pairs, REPEAT);
    let same = typed == repeated;
    repeated.zeroize();
    if !same {
        typed.zeroize();
        return Entry::Mismatch;
    }
    write_only(typed).map_or(Entry::Keep, Entry::New)
}

/// Removes every field `name` from `pairs`; the last value, moved out.
pub(crate) fn take(pairs: &mut Vec<(String, String)>, name: &str) -> String {
    let mut found = String::new();
    pairs.retain_mut(|(field, value)| {
        if field == name {
            found.zeroize();
            found = mem::take(value);
            false
        } else {
            true
        }
    });
    found
}

/// How long a secret may be, in characters, and the sentence saying so.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Length {
    /// Fewest characters.
    minimum: usize,
    /// Most characters.
    maximum: usize,
    /// The localized rule.
    rule: MessageKey,
}

impl Length {
    /// From `minimum` to `maximum` characters, as `rule` says.
    pub(crate) const fn new(minimum: usize, maximum: usize, rule: MessageKey) -> Self {
        Self {
            minimum,
            maximum,
            rule,
        }
    }

    /// Whether `secret` has an allowed number of characters.
    pub(crate) fn fits(self, secret: &SecretString) -> bool {
        (self.minimum..=self.maximum).contains(&secret.expose_secret().chars().count())
    }
}

/// One non-secret field of a secret dialog: a key name typed, or an account chosen.
#[derive(Debug, Clone)]
pub(crate) struct Plain {
    /// The form field.
    name: &'static str,
    /// Localized label.
    label: String,
    /// Localized help; empty when none.
    help: String,
    /// The value as typed or chosen.
    value: String,
    /// The accounts to choose from; empty for a typed value.
    choices: Vec<String>,
}

impl Plain {
    /// A field `name` labelled `label`, with `help` under it, holding `value`.
    pub(crate) fn new(
        locale: Locale,
        (name, label, help): (&'static str, MessageKey, MessageKey),
        value: &str,
    ) -> Self {
        Self {
            name,
            label: tr(locale, label, None),
            help: tr(locale, help, None),
            value: value.to_owned(),
            choices: Vec::new(),
        }
    }

    /// Offers `choices` in a list instead of a text field.
    pub(crate) fn choosing(mut self, choices: Vec<String>) -> Self {
        self.choices = choices;
        self
    }

    /// The form field.
    pub(crate) const fn name(&self) -> &'static str {
        self.name
    }

    /// Localized label.
    pub(crate) fn label(&self) -> &str {
        &self.label
    }

    /// Localized help.
    pub(crate) fn help(&self) -> &str {
        &self.help
    }

    /// The value as typed or chosen.
    pub(crate) fn value(&self) -> &str {
        &self.value
    }

    /// The choices of a list.
    pub(crate) fn choices(&self) -> &[String] {
        &self.choices
    }
}

/// A secret dialog: its title, what the secret is, and the errors of the last try.
#[derive(Debug, Template)]
#[template(path = "partials/secret_dialog.html")]
pub(crate) struct SecretDialog {
    /// Locale carrier.
    shell: Shell,
    /// Localized title.
    title: String,
    /// Localized text above the fields; empty when none.
    intro: String,
    /// Why nothing can be set here, shown instead of the form; empty when the form shows.
    refusal: String,
    /// Where the form posts: the page action with the object in its query string.
    post_to: String,
    /// The fail-safe note of a management change, whose Apply confirms it; empty for a
    /// plain write.
    fail_safe: String,
    /// The non-secret field, when the dialog has one.
    plain: Option<Plain>,
    /// Localized error under the non-secret field.
    plain_error: String,
    /// Localized label of the new value.
    label: String,
    /// Localized help under the new value.
    help: String,
    /// The length rule.
    length: Option<Length>,
    /// Localized error under the new value.
    secret_error: String,
    /// Localized error under its repetition.
    repeat_error: String,
}

localized!(SecretDialog);

impl SecretDialog {
    /// The dialog titled `title` with `$name` set to `name`, posting to `post_to`, asking
    /// for the secret labelled `label` with `help` under it.
    pub(crate) fn new(
        locale: Locale,
        (title, name): (MessageKey, &str),
        post_to: String,
        (label, help): (MessageKey, MessageKey),
    ) -> Self {
        let mut args = FluentArgs::new();
        args.set("name", name.to_owned());
        Self {
            shell: fragment_shell(locale),
            title: tr(locale, title, Some(&args)),
            intro: String::new(),
            refusal: String::new(),
            post_to,
            fail_safe: String::new(),
            plain: None,
            plain_error: String::new(),
            label: tr(locale, label, None),
            help: tr(locale, help, None),
            length: None,
            secret_error: String::new(),
            repeat_error: String::new(),
        }
    }

    /// Shows `intro` above the fields.
    pub(crate) fn intro(mut self, intro: MessageKey) -> Self {
        self.intro = tr(self.shell.locale(), intro, None);
        self
    }

    /// Checks `length` in the browser too.
    pub(crate) const fn bounded(mut self, length: Length) -> Self {
        self.length = Some(length);
        self
    }

    /// A management change: the fail-safe note, and Apply confirms it.
    pub(crate) fn management(mut self) -> Self {
        let mut args = FluentArgs::new();
        args.set("minutes", FAIL_SAFE_MINUTES.to_string());
        self.fail_safe = tr(
            self.shell.locale(),
            keys::WEB_SYSTEM_USERS_FAIL_SAFE,
            Some(&args),
        );
        self
    }

    /// Adds the non-secret field `plain` above the secret.
    pub(crate) fn with_plain(mut self, plain: Plain) -> Self {
        self.plain = Some(plain);
        self
    }

    /// Shows `refusal` instead of the form.
    pub(crate) fn refused(mut self, refusal: String) -> Self {
        self.refusal = refusal;
        self
    }

    /// The length rule, for the browser's check: (fewest, most) characters.
    fn bounds(&self) -> Option<(usize, usize)> {
        self.length.map(|length| (length.minimum, length.maximum))
    }

    /// The localized length rule; empty without one.
    fn rule(&self) -> String {
        self.length.map_or_else(String::new, |length| {
            tr(self.shell.locale(), length.rule, None)
        })
    }

    /// The ids describing the new value: its help and its error.
    fn secret_described(&self) -> String {
        described("secret-new", !self.help.is_empty(), &self.secret_error)
    }

    /// The ids describing the repetition: its error.
    fn repeat_described(&self) -> String {
        described("secret-repeat", false, &self.repeat_error)
    }

    /// The ids describing the non-secret field: its help and its error.
    fn plain_described(&self) -> String {
        let help = self
            .plain
            .as_ref()
            .is_some_and(|plain| !plain.help.is_empty());
        described("secret-plain", help, &self.plain_error)
    }

    /// The dialog, the answer to its `GET`.
    pub(crate) fn show(&self) -> Response {
        respond::in_dialog(errors::render(self))
    }

    /// The dialog again with `error` under the new value, as 422.
    pub(crate) fn secret_error(mut self, error: String) -> Answer {
        self.secret_error = error;
        respond::in_dialog(respond::unprocessable(&self)).into()
    }

    /// The dialog again saying the two entries differ, as 422.
    pub(crate) fn mismatch(mut self) -> Answer {
        self.repeat_error = tr(self.shell.locale(), keys::WEB_SECRET_MISMATCH, None);
        respond::in_dialog(respond::unprocessable(&self)).into()
    }

    /// The dialog again saying the length rule, as 422.
    pub(crate) fn out_of_bounds(self) -> Answer {
        let rule = self.rule();
        self.secret_error(rule)
    }

    /// The dialog again with `error` under the non-secret field, as 422.
    pub(crate) fn plain_error(mut self, error: String) -> Answer {
        self.plain_error = error;
        respond::in_dialog(respond::unprocessable(&self)).into()
    }

    /// The refusal again, as 422.
    pub(crate) fn refusal(self) -> Answer {
        respond::in_dialog(respond::unprocessable(&self)).into()
    }
}

/// The ids describing the input `id`: its help when it has one, then its error.
fn described(id: &str, help: bool, error: &str) -> String {
    let mut ids = Vec::new();
    if help {
        ids.push(format!("{id}-help"));
    }
    if !error.is_empty() {
        ids.push(format!("{id}-error"));
    }
    ids.join(" ")
}

/// The non-secret field `name` of `pairs`, trimmed; empty when absent.
pub(crate) fn plain_value(pairs: &[(String, String)], name: &str) -> String {
    pairs
        .iter()
        .rev()
        .find(|(field, _)| field == name)
        .map(|(_, value)| value.trim().to_owned())
        .unwrap_or_default()
}
