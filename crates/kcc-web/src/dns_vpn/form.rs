//! The dialog forms of the DNS and VPN pages: inputs with their labels, help and errors,
//! shown again with the values as typed when a check fails.

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
    page_kit::{context::fragment_shell, respond},
};

/// Field errors: the field name and its message.
pub(crate) type Errors = Vec<(&'static str, MessageKey)>;

/// The submitted fields of a form; the last value of a repeated name counts.
#[derive(Debug, Default)]
pub(crate) struct Values(Vec<(String, String)>);

impl Values {
    /// The fields of one submission.
    pub(crate) const fn new(pairs: Vec<(String, String)>) -> Self {
        Self(pairs)
    }

    /// The value of `name` as typed; empty when absent.
    pub(crate) fn get(&self, name: &str) -> &str {
        self.0
            .iter()
            .rev()
            .find(|(field, _)| field == name)
            .map_or("", |(_, value)| value.as_str())
    }
}

/// What kind of control an input is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// One line of text.
    Text,
    /// A file to upload.
    File,
    /// A value carried along, not shown.
    Hidden,
    /// A drop-down list.
    Select,
    /// Radio buttons.
    Radio,
    /// A write-only secret: always shown empty, never filled with a value.
    Secret,
}

/// One option of a select or a radio group.
#[derive(Debug, Clone)]
pub(crate) struct Choice {
    /// The submitted value.
    value: String,
    /// The localized label.
    label: String,
}

impl Choice {
    /// The option `value`, labelled `label`.
    pub(crate) fn word(locale: Locale, value: &str, label: MessageKey) -> Self {
        Self {
            value: value.to_owned(),
            label: tr(locale, label, None),
        }
    }

    /// The option `value`, labelled with itself, such as an interface name.
    pub(crate) fn plain(value: String) -> Self {
        Self {
            label: value.clone(),
            value,
        }
    }
}

/// One input of a form.
#[derive(Debug)]
struct Input {
    /// Element id.
    id: String,
    /// Field name.
    name: &'static str,
    /// Localized label.
    label: String,
    /// Control kind.
    kind: Kind,
    /// Value as typed, or the current one.
    value: String,
    /// Localized error; empty when none.
    error: String,
    /// Localized help; empty when none.
    help: String,
    /// The `kind` radio values this input belongs to; empty when always shown.
    show: &'static str,
    /// Options of a select or a radio group.
    choices: Vec<Choice>,
}

impl Input {
    /// The ids the control is described by: its error and its help.
    fn described_by(&self) -> String {
        let mut ids = Vec::new();
        if !self.error.is_empty() {
            ids.push(format!("{}-error", self.id));
        }
        if !self.help.is_empty() {
            ids.push(format!("{}-help", self.id));
        }
        ids.join(" ")
    }

    /// The options with whether each is chosen: the input's value, else the first option
    /// of a radio group.
    fn options(&self) -> Vec<(&Choice, bool)> {
        self.choices
            .iter()
            .enumerate()
            .map(|(index, choice)| {
                let chosen = if self.value.is_empty() {
                    self.kind == Kind::Radio && index == 0
                } else {
                    choice.value == self.value
                };
                (choice, chosen)
            })
            .collect()
    }
}

/// A dialog form; it posts to the page and its outcome lands in `#page-outcome`.
#[derive(Template)]
#[template(path = "partials/dns_vpn_form.html")]
pub(crate) struct FormDialog {
    /// Locale carrier.
    shell: Shell,
    /// Localized title.
    title: String,
    /// Localized text above the inputs; empty when none.
    intro: String,
    /// Localized problem with the whole form; empty when none.
    problem: String,
    /// Where the form posts.
    post_to: String,
    /// The inputs.
    inputs: Vec<Input>,
    /// Localized label of the submit button.
    submit: String,
    /// Whether the form uploads a file.
    multipart: bool,
}

localized!(FormDialog);

impl FormDialog {
    /// A form titled `title` posting to `post_to`, submitted with Apply.
    pub(crate) fn new(locale: Locale, title: MessageKey, post_to: String) -> Self {
        Self {
            shell: fragment_shell(locale),
            title: tr(locale, title, None),
            intro: String::new(),
            problem: String::new(),
            post_to,
            inputs: Vec::new(),
            submit: tr(locale, keys::COMMON_APPLY, None),
            multipart: false,
        }
    }

    /// Shows `text` above the inputs.
    pub(crate) fn intro(mut self, text: MessageKey) -> Self {
        self.intro = tr(self.shell.locale(), text, None);
        self
    }

    /// Labels the submit button `label`.
    pub(crate) fn submit(mut self, label: MessageKey) -> Self {
        self.submit = tr(self.shell.locale(), label, None);
        self
    }

    /// Uploads with `multipart/form-data`.
    pub(crate) const fn multipart(mut self) -> Self {
        self.multipart = true;
        self
    }

    /// Adds an input `name` of `kind`, labelled `label`, offering `choices`.
    fn input(
        mut self,
        (name, key): (&'static str, MessageKey),
        kind: Kind,
        choices: Vec<Choice>,
    ) -> Self {
        let label = tr(self.shell.locale(), key, None);
        self.inputs.push(Input {
            id: format!("form-{name}"),
            name,
            label,
            kind,
            value: String::new(),
            error: String::new(),
            help: String::new(),
            show: "",
            choices,
        });
        self
    }

    /// Adds a text input `name` labelled `label`.
    pub(crate) fn text(self, name: &'static str, label: MessageKey) -> Self {
        self.input((name, label), Kind::Text, Vec::new())
    }

    /// Adds a file input `name` labelled `label`.
    pub(crate) fn file(self, name: &'static str, label: MessageKey) -> Self {
        self.input((name, label), Kind::File, Vec::new())
    }

    /// Adds a write-only secret input `name` labelled `label`; it is never filled.
    pub(crate) fn secret(self, name: &'static str, label: MessageKey) -> Self {
        self.input((name, label), Kind::Secret, Vec::new())
    }

    /// Carries `name` along, not shown; its value comes with [`FormDialog::values`].
    pub(crate) fn hidden(self, name: &'static str) -> Self {
        self.input((name, keys::WEB_DNS_NONE), Kind::Hidden, Vec::new())
    }

    /// Adds a drop-down list `name` labelled `label`.
    pub(crate) fn select(
        self,
        name: &'static str,
        label: MessageKey,
        choices: Vec<Choice>,
    ) -> Self {
        self.input((name, label), Kind::Select, choices)
    }

    /// Adds radio buttons `name` labelled `label`; the first is chosen until a value is.
    pub(crate) fn radio(self, name: &'static str, label: MessageKey, choices: Vec<Choice>) -> Self {
        self.input((name, label), Kind::Radio, choices)
    }

    /// Shows `help` under the last input.
    pub(crate) fn help(mut self, help: MessageKey) -> Self {
        let text = tr(self.shell.locale(), help, None);
        if let Some(input) = self.inputs.last_mut() {
            input.help = text;
        }
        self
    }

    /// Shows the last input only while the `kind` radio holds one of `kinds`
    /// (space-separated).
    pub(crate) fn shown_for(mut self, kinds: &'static str) -> Self {
        if let Some(input) = self.inputs.last_mut() {
            input.show = kinds;
        }
        self
    }

    /// Fills every input with its submitted value; files and secrets stay empty.
    pub(crate) fn values(mut self, values: &Values) -> Self {
        for input in &mut self.inputs {
            if !matches!(input.kind, Kind::File | Kind::Secret) {
                values.get(input.name).clone_into(&mut input.value);
            }
        }
        self
    }

    /// Shows each of `errors` under its input; an error naming no input shows above.
    pub(crate) fn errors(mut self, errors: &Errors) -> Self {
        let locale = self.shell.locale();
        for (name, key) in errors {
            let text = tr(locale, *key, None);
            match self.inputs.iter_mut().find(|input| input.name == *name) {
                Some(input) => input.error = text,
                None => self.problem = text,
            }
        }
        self
    }

    /// Shows `text` under the input `name`, after any error it already shows.
    pub(crate) fn error(mut self, name: &str, text: &str) -> Self {
        if let Some(input) = self.inputs.iter_mut().find(|input| input.name == name) {
            if !input.error.is_empty() {
                input.error.push(' ');
            }
            input.error.push_str(text);
        }
        self
    }

    /// Shows `text` above the inputs as a problem with the whole form.
    pub(crate) fn problem(mut self, text: String) -> Self {
        self.problem = text;
        self
    }

    /// The dialog, the answer to its `GET`.
    pub(crate) fn show(&self) -> Response {
        errors::render(self)
    }

    /// The dialog again with its errors: 422, shown in the shared dialog.
    pub(crate) fn invalid(&self) -> Response {
        respond::in_dialog(respond::unprocessable(self))
    }
}
