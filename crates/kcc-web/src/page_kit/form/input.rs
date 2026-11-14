//! Building one input of a dialog form and the options it offers.

use kcc_i18n::{
    bundle::{MessageKey, tr},
    locale::Locale,
};

use super::{Choice, Input, Kind};

/// Longest value of a required text input when it sets no other limit, in characters.
const TEXT_CHARS: usize = 128;

impl Choice {
    /// The option `value`, labelled `label` in `locale`.
    pub(crate) fn word(locale: Locale, value: &str, label: MessageKey) -> Self {
        Self {
            value: value.to_owned(),
            label: tr(locale, label, None),
            checked: false,
        }
    }

    /// The option `value`, labelled with itself, such as an interface name.
    pub(crate) fn plain(value: &str) -> Self {
        Self {
            value: value.to_owned(),
            label: value.to_owned(),
            checked: false,
        }
    }

    /// The option shown checked when `checked`, in a checkbox group.
    pub(crate) const fn checked(mut self, checked: bool) -> Self {
        self.checked = checked;
        self
    }
}

impl Input {
    /// An input `name` of `kind`, labelled `label`, empty and optional.
    const fn of(name: &'static str, label: Option<MessageKey>, kind: Kind) -> Self {
        Self {
            name,
            id: None,
            label,
            help: None,
            kind,
            value: String::new(),
            error: String::new(),
            required: false,
            max_chars: None,
            bounds: None,
            rule: None,
            show: "",
            choices: Vec::new(),
            mono: false,
            group: None,
            field_type: "text",
        }
    }

    /// A required line of text `name` of at most 128 characters, labelled `label`,
    /// showing `value`.
    pub(crate) fn new(name: &'static str, label: MessageKey, value: String) -> Self {
        Self {
            value,
            required: true,
            max_chars: Some(TEXT_CHARS),
            ..Self::of(name, Some(label), Kind::Text)
        }
    }

    /// An optional line of text `name` labelled `label`, without limits.
    pub(crate) const fn text(name: &'static str, label: MessageKey) -> Self {
        Self::of(name, Some(label), Kind::Text)
    }

    /// The shared text field component `name` labelled `label`, showing `value`.
    pub(crate) fn field(name: &'static str, label: MessageKey, value: String) -> Self {
        Self {
            value,
            ..Self::of(name, Some(label), Kind::Field)
        }
    }

    /// A file input `name` labelled `label`.
    pub(crate) const fn file(name: &'static str, label: MessageKey) -> Self {
        Self::of(name, Some(label), Kind::File)
    }

    /// A write-only secret input `name` labelled `label`; it is never filled.
    pub(crate) const fn secret(name: &'static str, label: MessageKey) -> Self {
        Self::of(name, Some(label), Kind::Secret)
    }

    /// Carries `name` along with `value`, not shown.
    pub(crate) fn hidden(name: &'static str, value: String) -> Self {
        Self {
            value,
            ..Self::of(name, None, Kind::Hidden)
        }
    }

    /// One checkbox `name` labelled `label`, checked when `checked`.
    pub(crate) fn check(name: &'static str, label: MessageKey, checked: bool) -> Self {
        Self {
            value: if checked { "on" } else { "" }.to_owned(),
            ..Self::of(name, Some(label), Kind::Check)
        }
    }

    /// Shows `value`; a file or a secret input stays empty.
    pub(crate) fn value(mut self, value: String) -> Self {
        if !matches!(self.kind, Kind::File | Kind::Secret) {
            self.value = value;
        }
        self
    }

    /// Makes the input a drop-down list of `choices`.
    pub(crate) fn select(mut self, choices: Vec<Choice>) -> Self {
        self.kind = Kind::Select;
        self.choices = choices;
        self
    }

    /// Makes the input radio buttons of `choices`.
    pub(crate) fn radio(mut self, choices: Vec<Choice>) -> Self {
        self.kind = Kind::Radio;
        self.choices = choices;
        self
    }

    /// Makes the input a checkbox group of `choices`, each checked as it says.
    pub(crate) fn checks(mut self, choices: Vec<Choice>) -> Self {
        self.kind = Kind::Checks;
        self.choices = choices;
        self
    }

    /// Makes the input a whole number from `min` to `max`.
    pub(crate) const fn number(mut self, min: i64, max: i64) -> Self {
        self.kind = Kind::Number;
        self.bounds = Some((min, max));
        self.max_chars = None;
        self
    }

    /// Makes the field component an input of the HTML type `kind`, such as `time`.
    pub(crate) const fn typed(mut self, kind: &'static str) -> Self {
        self.kind = Kind::Field;
        self.field_type = kind;
        self
    }

    /// Limits the text to `max_chars` characters.
    pub(crate) const fn max_chars(mut self, max_chars: usize) -> Self {
        self.max_chars = Some(max_chars);
        self
    }

    /// Lets the input be empty.
    pub(crate) const fn optional(mut self) -> Self {
        self.required = false;
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

    /// Shows the input only while the `kind` radio holds one of `kinds` (space-separated).
    pub(crate) const fn shown_for(mut self, kinds: &'static str) -> Self {
        self.show = kinds;
        self
    }

    /// Names the element `id` instead of `<prefix>-<name>`.
    pub(crate) const fn id(mut self, id: &'static str) -> Self {
        self.id = Some(id);
        self
    }

    /// Sets the options' labels in the monospace face, for identifiers.
    pub(crate) const fn mono(mut self) -> Self {
        self.mono = true;
        self
    }

    /// Puts the input in the box of class `class` it shares with its grouped neighbours.
    pub(crate) const fn grouped(mut self, class: &'static str) -> Self {
        self.group = Some(class);
        self
    }

    /// The `type` of a text or number input.
    pub(super) const fn html_type(&self) -> &'static str {
        match self.kind {
            Kind::Number => "number",
            Kind::Field => self.field_type,
            Kind::Text
            | Kind::File
            | Kind::Hidden
            | Kind::Select
            | Kind::Radio
            | Kind::Checks
            | Kind::Check
            | Kind::Secret => "text",
        }
    }

    /// The longest value of a text input.
    pub(super) const fn limit(&self) -> Option<usize> {
        match self.kind {
            Kind::Text => self.max_chars,
            Kind::Number
            | Kind::Field
            | Kind::File
            | Kind::Hidden
            | Kind::Select
            | Kind::Radio
            | Kind::Checks
            | Kind::Check
            | Kind::Secret => None,
        }
    }
}
