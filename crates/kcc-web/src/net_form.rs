//! The dialog forms of the network pages.
//!
//! A form has a title naming the object, an optional note, inputs with their client-side
//! constraints and server-side errors, and one submit button.
//!
//! An input's `data-kcc-invalid` message is the localized rule the browser shows when
//! its constraint check fails, so nothing is sent; the server checks the same rule again
//! and answers the dialog with the field error as 422, the values as typed.

use askama::Template;
use axum::response::Response;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};

use crate::{
    errors,
    page::{Localize as _, Shell},
    page_kit::{
        context::fragment_shell,
        outcome::Failure,
        respond,
        submit::{Form, Invalid},
    },
};

/// Longest text input value when the input sets no other limit, in characters.
const TEXT_CHARS: usize = 128;

/// A dialog form.
#[derive(Template)]
#[template(path = "partials/net_form.html")]
pub(crate) struct FormDialog {
    /// Locale carrier.
    shell: Shell,
    /// The localized title.
    title: String,
    /// A localized paragraph above the inputs.
    note: Option<String>,
    /// Where the form posts.
    post_to: String,
    /// The inputs, in order.
    inputs: Vec<Input>,
    /// The submit button.
    submit: MessageKey,
}

localized!(FormDialog);

impl FormDialog {
    /// A form titled `title` (localized) in `locale`, posting to `post_to`.
    pub(crate) const fn new(locale: Locale, title: String, post_to: String) -> Self {
        Self {
            shell: fragment_shell(locale),
            title,
            note: None,
            post_to,
            inputs: Vec::new(),
            submit: keys::COMMON_APPLY,
        }
    }

    /// Adds `input`.
    pub(crate) fn with_input(mut self, input: Input) -> Self {
        self.inputs.push(input);
        self
    }

    /// Labels the submit button with `submit`.
    pub(crate) const fn with_submit(mut self, submit: MessageKey) -> Self {
        self.submit = submit;
        self
    }

    /// Shows `error` (localized) under the input named `name`.
    pub(crate) fn with_error(mut self, name: &str, error: String) -> Self {
        if let Some(input) = self.inputs.iter_mut().find(|input| input.name == name) {
            input.error = error;
        }
        self
    }

    /// The dialog, the answer to its `GET`.
    pub(crate) fn show(&self) -> Response {
        respond::in_dialog(errors::render(self))
    }

    /// The dialog again with its errors: 422, shown in the shared dialog.
    pub(crate) fn invalid(&self) -> Response {
        respond::in_dialog(respond::unprocessable(self))
    }

    /// The dialog, which also shows a change the domain could not plan, under the input
    /// named `field`.
    pub(crate) const fn refusing_at(self, field: &'static str) -> FieldDialog {
        FieldDialog {
            dialog: self,
            field,
        }
    }

    /// The localized label of `input`.
    fn label(&self, input: &Input) -> String {
        tr(self.shell.locale(), input.label, None)
    }

    /// The localized help of `input`.
    fn help(&self, input: &Input) -> Option<String> {
        input.help.map(|key| tr(self.shell.locale(), key, None))
    }

    /// The localized rule the browser shows when the constraint check of `input` fails.
    fn rule(&self, input: &Input) -> Option<String> {
        input.rule.map(|key| tr(self.shell.locale(), key, None))
    }
}

impl Form for FormDialog {
    fn answer_invalid(self, invalid: Invalid, locale: Locale) -> Response {
        invalid
            .into_findings()
            .into_iter()
            .fold(self, |dialog, (field, rule)| {
                dialog.with_error(field, tr(locale, rule, None))
            })
            .invalid()
    }
}

/// A dialog that shows a change the domain could not plan under one of its inputs.
pub(crate) struct FieldDialog {
    /// The dialog.
    dialog: FormDialog,
    /// The name of the input that shows the refusal.
    field: &'static str,
}

impl Form for FieldDialog {
    fn answer_invalid(self, invalid: Invalid, locale: Locale) -> Response {
        self.dialog.answer_invalid(invalid, locale)
    }

    fn answer_refused(self, failure: Failure, _locale: Locale) -> Response {
        self.dialog
            .with_error(self.field, failure.message().to_owned())
            .invalid()
    }
}

/// One input of a dialog form.
#[derive(Debug, Clone)]
pub(crate) struct Input {
    /// Form field name; the element id is `net-<name>`.
    name: &'static str,
    /// The label.
    label: MessageKey,
    /// Help under the input.
    help: Option<MessageKey>,
    /// The value shown: the current one, or the one typed.
    value: String,
    /// The localized error under the input; empty when none.
    error: String,
    /// The kind of control and its constraints.
    control: Control,
    /// Whether the value may not be empty.
    required: bool,
    /// The rule the browser shows when the constraint check fails.
    rule: Option<MessageKey>,
}

/// The kind of an input and its client-side constraints.
#[derive(Debug, Clone)]
enum Control {
    /// Free text of at most `max_chars` characters.
    Text {
        /// Longest value in characters.
        max_chars: usize,
    },
    /// A whole number from `min` to `max`.
    Number {
        /// Smallest value.
        min: i64,
        /// Largest value.
        max: i64,
    },
    /// One of the listed choices.
    Select(Vec<Choice>),
}

/// One choice of a select input.
#[derive(Debug, Clone)]
pub(crate) struct Choice {
    /// The value sent.
    value: String,
    /// The localized label.
    label: String,
}

impl Choice {
    /// A choice whose label is the value itself, such as an interface name.
    pub(crate) fn plain(value: &str) -> Self {
        Self {
            value: value.to_owned(),
            label: value.to_owned(),
        }
    }

    /// A choice sending `value` labelled by `key` in `locale`.
    pub(crate) fn keyed(value: &str, key: MessageKey, locale: Locale) -> Self {
        Self {
            value: value.to_owned(),
            label: tr(locale, key, None),
        }
    }
}

impl Input {
    /// A required text input `name` labelled `label`, showing `value`.
    pub(crate) const fn new(name: &'static str, label: MessageKey, value: String) -> Self {
        Self {
            name,
            label,
            help: None,
            value,
            error: String::new(),
            control: Control::Text {
                max_chars: TEXT_CHARS,
            },
            required: true,
            rule: None,
        }
    }

    /// Limits the text to `max_chars` characters.
    pub(crate) fn max_chars(mut self, max_chars: usize) -> Self {
        self.control = Control::Text { max_chars };
        self
    }

    /// Makes the input a whole number from `min` to `max`.
    pub(crate) fn number(mut self, min: i64, max: i64) -> Self {
        self.control = Control::Number { min, max };
        self
    }

    /// Lets the input be empty.
    pub(crate) const fn optional(mut self) -> Self {
        self.required = false;
        self
    }

    /// Makes the input a select of `choices`.
    pub(crate) fn select(mut self, choices: Vec<Choice>) -> Self {
        self.control = Control::Select(choices);
        self
    }

    /// Shows `rule` when the browser's constraint check fails.
    pub(crate) const fn rule(mut self, rule: MessageKey) -> Self {
        self.rule = Some(rule);
        self
    }

    /// Shows `help` under the input.
    pub(crate) const fn help(mut self, help: MessageKey) -> Self {
        self.help = Some(help);
        self
    }

    /// The element id.
    fn id(&self) -> String {
        format!("net-{}", self.name)
    }

    /// The ids of the help and the error, for `aria-describedby`; empty when none.
    fn described_by(&self) -> String {
        let id = self.id();
        let mut parts = Vec::new();
        if self.help.is_some() {
            parts.push(format!("{id}-help"));
        }
        if !self.error.is_empty() {
            parts.push(format!("{id}-error"));
        }
        parts.join(" ")
    }

    /// The choices of a select input.
    fn choices(&self) -> Option<&[Choice]> {
        match &self.control {
            Control::Select(choices) => Some(choices),
            Control::Text { max_chars: _ } | Control::Number { min: _, max: _ } => None,
        }
    }

    /// The `type` of a text or number input.
    const fn kind(&self) -> &'static str {
        match self.control {
            Control::Number { min: _, max: _ } => "number",
            Control::Text { max_chars: _ } | Control::Select(_) => "text",
        }
    }

    /// The longest value of a text input.
    const fn limit(&self) -> Option<usize> {
        match self.control {
            Control::Text { max_chars } => Some(max_chars),
            Control::Number { min: _, max: _ } | Control::Select(_) => None,
        }
    }

    /// The bounds of a number input.
    const fn bounds(&self) -> Option<(i64, i64)> {
        match self.control {
            Control::Number { min, max } => Some((min, max)),
            Control::Text { max_chars: _ } | Control::Select(_) => None,
        }
    }
}
