//! Building a dialog form, and what its template asks of it.

use axum::response::Response;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};

use super::{Choice, Errors, FormDialog, Input, Kind, Problem, Refusal};
use crate::{
    errors,
    page::Localize as _,
    page_kit::{context::fragment_shell, request::Params, respond},
};

impl FormDialog {
    /// A form titled `title` (localized) in `locale`, posting to `post_to`, submitted
    /// with Apply; its element ids are `form-<name>`.
    pub(crate) fn titled(locale: Locale, title: String, post_to: String) -> Self {
        Self {
            shell: fragment_shell(locale),
            title,
            leading_break: false,
            intro: String::new(),
            problem: String::new(),
            problem_at: Problem::Above,
            post_to,
            multipart: false,
            inputs: Vec::new(),
            closing: String::new(),
            submit: tr(locale, keys::COMMON_APPLY, None),
            button: "primary",
            prefix: "form",
            network: false,
            refusal: Refusal::Region,
        }
    }

    /// A form titled `title` in `locale`, posting to `post_to`.
    pub(crate) fn new(locale: Locale, title: MessageKey, post_to: String) -> Self {
        Self::titled(locale, tr(locale, title, None), post_to)
    }

    /// A form of the network pages: element ids `net-<name>`, help named before the
    /// error, and its `GET` answer shown in the shared dialog.
    pub(crate) fn network(locale: Locale, title: String, post_to: String) -> Self {
        Self {
            prefix: "net",
            network: true,
            ..Self::titled(locale, title, post_to)
        }
    }

    /// Names the element ids `<prefix>-<name>`.
    pub(crate) const fn ids(mut self, prefix: &'static str) -> Self {
        self.prefix = prefix;
        self
    }

    /// Adds `input`.
    pub(crate) fn with_input(mut self, input: Input) -> Self {
        self.inputs.push(input);
        self
    }

    /// Shows `text` above the form.
    pub(crate) fn intro(mut self, text: MessageKey) -> Self {
        self.intro = self.t(text);
        self
    }

    /// Shows `text` (localized) under the inputs.
    pub(crate) fn closing(mut self, text: String) -> Self {
        self.closing = text;
        self
    }

    /// Labels the submit button `label`.
    pub(crate) fn submit(mut self, label: MessageKey) -> Self {
        self.submit = self.t(label);
        self
    }

    /// Uploads with `multipart/form-data`.
    pub(crate) const fn multipart(mut self) -> Self {
        self.multipart = true;
        self
    }

    /// Starts the dialog with a line break.
    pub(crate) const fn leading_break(mut self) -> Self {
        self.leading_break = true;
        self
    }

    /// Shows a problem with the whole form at `place`.
    pub(crate) const fn problem_at(mut self, place: Problem) -> Self {
        self.problem_at = place;
        self
    }

    /// Shows a change the domain could not plan under the input `field`.
    pub(crate) const fn refusing_at(mut self, field: &'static str) -> Self {
        self.refusal = Refusal::Field(field);
        self
    }

    /// Shows a change the domain could not plan as the form's problem.
    pub(crate) const fn refusing_in_dialog(mut self) -> Self {
        self.refusal = Refusal::Problem;
        self
    }

    /// Shows `value` in the input `name`.
    pub(crate) fn with_value(mut self, name: &str, value: String) -> Self {
        if let Some(input) = self.inputs.iter_mut().find(|input| input.name == name) {
            *input = input.clone().value(value);
        }
        self
    }

    /// Fills every input with its submitted value; files, secrets and checkboxes stay as
    /// they are.
    pub(crate) fn values(mut self, values: &Params) -> Self {
        for input in &mut self.inputs {
            if !matches!(
                input.kind,
                Kind::File | Kind::Secret | Kind::Check | Kind::Checks
            ) {
                values.text(input.name).clone_into(&mut input.value);
            }
        }
        self
    }

    /// Shows `error` (localized) under the input `name`, instead of any it shows.
    pub(crate) fn with_error(mut self, name: &str, error: String) -> Self {
        if let Some(input) = self.inputs.iter_mut().find(|input| input.name == name) {
            input.error = error;
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

    /// Shows each of `errors` under its input; an error naming no input shows as the
    /// form's problem.
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

    /// Shows `text` as a problem with the whole form.
    pub(crate) fn problem(mut self, text: String) -> Self {
        self.problem = text;
        self
    }

    /// The dialog, the answer to its `GET`.
    pub(crate) fn show(&self) -> Response {
        let shown = errors::render(self);
        if self.network {
            respond::in_dialog(shown)
        } else {
            shown
        }
    }

    /// The dialog again with its errors: 422, shown in the shared dialog.
    pub(crate) fn invalid(&self) -> Response {
        respond::in_dialog(respond::unprocessable(self))
    }

    /// The element id of `input`.
    pub(super) fn id(&self, input: &Input) -> String {
        input
            .id
            .map_or_else(|| format!("{}-{}", self.prefix, input.name), str::to_owned)
    }

    /// The localized label of `input`; empty for a hidden one.
    pub(super) fn label(&self, input: &Input) -> String {
        input.label.map_or_default(|key| self.t(key))
    }

    /// The localized help of `input`; empty when none.
    pub(super) fn help(&self, input: &Input) -> String {
        input.help.map_or_default(|key| self.t(key))
    }

    /// The localized rule the browser shows when the constraint check of `input` fails.
    pub(super) fn rule(&self, input: &Input) -> Option<String> {
        input.rule.map(|key| self.t(key))
    }

    /// The ids of the help and the error of `input`, for `aria-describedby`; empty when
    /// none.
    pub(super) fn described_by(&self, input: &Input) -> String {
        let id = self.id(input);
        let help = input.help.map(|_key| format!("{id}-help"));
        let error = (!input.error.is_empty()).then(|| format!("{id}-error"));
        let ids = if self.network {
            [help, error]
        } else {
            [error, help]
        };
        ids.into_iter().flatten().collect::<Vec<_>>().join(" ")
    }

    /// The options of `input` with whether each is chosen: the input's value, else the
    /// first option of a radio group (on the network pages, an empty value chooses an
    /// empty option).
    pub(super) fn options<'input>(&self, input: &'input Input) -> Vec<(&'input Choice, bool)> {
        input
            .choices
            .iter()
            .enumerate()
            .map(|(index, choice)| {
                let chosen = if input.value.is_empty() && !self.network {
                    input.kind == Kind::Radio && index == 0
                } else {
                    choice.value == input.value
                };
                (choice, chosen)
            })
            .collect()
    }

    /// The class of the box the input at `index` opens, when it is the first of a group.
    #[expect(
        clippy::trivially_copy_pass_by_ref,
        reason = "askama passes a template's method arguments by reference"
    )]
    pub(super) fn opens_group(&self, index: &usize) -> Option<&'static str> {
        let group = self.inputs.get(*index)?.group?;
        let previous = index
            .checked_sub(1)
            .and_then(|before| self.inputs.get(before))
            .and_then(|input| input.group);
        (previous != Some(group)).then_some(group)
    }

    /// Whether the input at `index` is the last of a group.
    #[expect(
        clippy::trivially_copy_pass_by_ref,
        reason = "askama passes a template's method arguments by reference"
    )]
    pub(super) fn closes_group(&self, index: &usize) -> bool {
        let group = self.inputs.get(*index).and_then(|input| input.group);
        let next = index
            .checked_add(1)
            .and_then(|after| self.inputs.get(after))
            .and_then(|input| input.group);
        group.is_some() && next != group
    }
}
