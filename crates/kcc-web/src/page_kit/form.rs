//! The dialog forms of the domain pages, from a one-field edit to a whole configuration.
//!
//! A form has a title, an optional text above it, its inputs and one submit button. An
//! input carries its label, its value (the current one, or the one typed; a secret is
//! never filled), its help, its client-side constraints and, in `data-kcc-invalid`, the
//! localized rule the browser shows when they fail. The server checks the same values
//! again: a value that fails comes back into the dialog as 422 under its input, the values
//! as typed. An input with `data-show` appears only for the chosen `kind` radio (CSS
//! `:has`), so the form needs no script.
//!
//! A change the domain could not plan lands in the page's outcome region, unless the
//! form shows it under one of its inputs ([`FormDialog::refusing_at`]) or as its problem
//! ([`FormDialog::refusing_in_dialog`]).

mod answer;
mod dialog;
#[cfg(test)]
mod form_tests;
mod input;

use askama::Template;
use kcc_i18n::{bundle::MessageKey, keys};

use crate::page::{Localize as _, Shell};

/// Field errors: the field name and its message.
pub(crate) type Errors = Vec<(&'static str, MessageKey)>;

/// Where a dialog shows a problem with the whole form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Problem {
    /// A notice above the form.
    Above,
    /// A notice at the top of the form.
    Top,
    /// An alert under the inputs.
    Below,
}

/// Where a dialog shows a change the domain could not plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refusal {
    /// The page's outcome region.
    Region,
    /// Under the input of this name.
    Field(&'static str),
    /// As the form's problem.
    Problem,
}

/// A dialog form; it posts to the page and its outcome lands in `#page-outcome`.
#[derive(Template)]
#[template(path = "partials/kit_form.html")]
pub(crate) struct FormDialog {
    /// Locale carrier.
    shell: Shell,
    /// Localized title.
    title: String,
    /// Whether the dialog starts with a line break.
    leading_break: bool,
    /// Localized text above the form; empty when none.
    intro: String,
    /// Localized problem with the whole form; empty when none.
    problem: String,
    /// Where the problem shows.
    problem_at: Problem,
    /// Where the form posts.
    post_to: String,
    /// Whether the form uploads a file.
    multipart: bool,
    /// The inputs, in order.
    inputs: Vec<Input>,
    /// Localized text under the inputs; empty when none.
    closing: String,
    /// Localized label of the submit button.
    submit: String,
    /// The class modifier of the submit button: `primary`, or `danger` for one that
    /// destroys something.
    button: &'static str,
    /// The element ids are `<prefix>-<name>`.
    prefix: &'static str,
    /// Whether the form follows the network pages' conventions: a control names its help
    /// before its error in `aria-describedby`, an empty value chooses an empty option, and
    /// the answer to the dialog's `GET` goes into the shared dialog whatever the request
    /// targeted.
    network: bool,
    /// Where a change the domain could not plan shows.
    refusal: Refusal,
}

localized!(FormDialog);

/// What kind of control an input is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// One line of text; the browser does not check its spelling.
    Text,
    /// A whole number between its bounds.
    Number,
    /// The shared field component, of the input's HTML type.
    Field,
    /// A file to upload.
    File,
    /// A value carried along, not shown.
    Hidden,
    /// A drop-down list.
    Select,
    /// Radio buttons; the first is chosen until a value is.
    Radio,
    /// A group of checkboxes, each sending its value when checked.
    Checks,
    /// One checkbox, checked while the value is set; it sends `on`.
    Check,
    /// A write-only secret: always shown empty, never filled with a value.
    Secret,
}

/// One option of a select, a radio group or a checkbox group.
#[derive(Debug, Clone)]
pub(crate) struct Choice {
    /// The submitted value.
    value: String,
    /// The localized label.
    label: String,
    /// Whether a checkbox group shows it checked.
    checked: bool,
}

/// One input of a dialog form.
#[derive(Debug, Clone)]
pub(crate) struct Input {
    /// Field name.
    name: &'static str,
    /// Element id when it is not `<prefix>-<name>`.
    id: Option<&'static str>,
    /// The label; none for a hidden input.
    label: Option<MessageKey>,
    /// Help under the input.
    help: Option<MessageKey>,
    /// The control.
    kind: Kind,
    /// The value shown: the current one, or the one typed.
    value: String,
    /// The localized error under the input; empty when none.
    error: String,
    /// Whether the value may not be empty.
    required: bool,
    /// Longest text in characters.
    max_chars: Option<usize>,
    /// Smallest and largest number.
    bounds: Option<(i64, i64)>,
    /// The rule the browser shows when its constraint check fails.
    rule: Option<MessageKey>,
    /// The `kind` radio values the input is shown for, space-separated; empty when always.
    show: &'static str,
    /// The options of a select, a radio group or a checkbox group.
    choices: Vec<Choice>,
    /// Whether the options' labels are identifiers, set in the monospace face.
    mono: bool,
    /// The class of the box the input shares with its grouped neighbours.
    group: Option<&'static str>,
    /// The HTML type of a field component, such as `time`.
    field_type: &'static str,
}
