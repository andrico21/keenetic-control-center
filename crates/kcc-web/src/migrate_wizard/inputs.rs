//! Step 5: the inputs the plan needs, each shown only when needed. Passwords are
//! write-only fields (an empty field keeps one already typed); nothing typed is ever
//! shown again.

use askama::Template;
use fluent_bundle::FluentArgs;
use kcc_i18n::{bundle::tr, keys};

use super::{
    access::{Migration as _, Visit},
    needs::Needs,
    plan::Classified,
    target::problem_text,
    warnings::agreement_name,
};
use crate::{
    page::{Localize as _, Shell},
    page_kit::context::fragment_shell,
    wizard::{flow::Flow as _, store::StoreError},
};

/// The step's panel.
#[derive(Template)]
#[template(path = "partials/migrate_inputs.html")]
pub(super) struct Panel {
    /// Locale carrier.
    shell: Shell,
    /// Migration id.
    id: String,
    /// One password field per user.
    passwords: Vec<Password>,
    /// One checkbox per component.
    components: Vec<Component>,
    /// The components' error.
    component_error: String,
    /// The reconnect URL, when the plan changes how kcc reaches the router.
    reconnect: Option<String>,
    /// The reconnect URL's error.
    reconnect_error: String,
    /// One acceptance per agreement.
    agreements: Vec<Agreement>,
    /// Whether nothing is needed.
    nothing: bool,
    /// What still blocks the plan.
    blocked: Vec<String>,
    /// Why the inputs cannot be shown.
    problem: String,
}

localized!(Panel);

/// A password field.
struct Password {
    /// The user.
    user: String,
    /// The field's position.
    index: usize,
    /// The field's id and name.
    field: String,
    /// Whether a password was typed before.
    stored: bool,
    /// The field's error.
    error: String,
}

/// A component to install first.
struct Component {
    /// Its name.
    name: String,
    /// "3 settings need it".
    needed: String,
    /// Whether it is chosen.
    checked: bool,
}

/// An agreement to accept.
struct Agreement {
    /// `dpn` or `eula`.
    name: &'static str,
    /// Its localized name.
    label: String,
    /// Its text.
    text: String,
    /// Whether it is accepted.
    checked: bool,
    /// The checkbox's error.
    error: String,
}

/// What the form sent back, to show again with errors.
#[derive(Default)]
pub(super) struct Shown {
    /// Field errors by user.
    passwords: Vec<(String, String)>,
    /// Checked components.
    components: Option<Vec<String>>,
    /// The components' error.
    component_error: String,
    /// The typed reconnect URL.
    reconnect: Option<String>,
    /// Its error.
    reconnect_error: String,
    /// Accepted agreements, and the error of the others.
    agreements: Option<(Vec<String>, String)>,
    /// What still blocks the plan.
    blocked: Vec<String>,
}

impl Shown {
    /// With `error` beside the password of `user`.
    pub(super) fn password_error(mut self, user: &str, error: String) -> Self {
        self.passwords.push((user.to_owned(), error));
        self
    }

    /// With the `checked` components and their `error`.
    pub(super) fn components(mut self, checked: Vec<String>, error: String) -> Self {
        self.components = Some(checked);
        self.component_error = error;
        self
    }

    /// With the typed reconnect URL and its `error`.
    pub(super) fn reconnect(mut self, typed: String, error: String) -> Self {
        self.reconnect = Some(typed);
        self.reconnect_error = error;
        self
    }

    /// With the `accepted` agreements and the `error` of the others.
    pub(super) fn agreements(mut self, accepted: Vec<String>, error: String) -> Self {
        self.agreements = Some((accepted, error));
        self
    }

    /// With what still blocks the plan.
    pub(super) fn blocked(mut self, blocked: Vec<String>) -> Self {
        self.blocked = blocked;
        self
    }
}

impl Panel {
    /// The inputs of `visit`, with what the form sent in `shown`.
    ///
    /// # Errors
    ///
    /// Returns the read and opening failures of the typed passwords.
    // NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned
    // router session. Apart from that, reads only.
    pub(super) async fn new(visit: &Visit<'_>, shown: Shown) -> Result<Self, StoreError> {
        let locale = visit.services().user().locale();
        let record = visit.record();
        let mut panel = Self {
            shell: fragment_shell(locale),
            id: record.id().to_owned(),
            passwords: Vec::new(),
            components: Vec::new(),
            component_error: shown.component_error,
            reconnect: None,
            reconnect_error: shown.reconnect_error,
            agreements: Vec::new(),
            nothing: false,
            blocked: shown.blocked,
            problem: String::new(),
        };
        let analysis = match visit.analysis().await {
            Ok(found) => found,
            Err(problem) => {
                panel.problem = problem_text(&problem, locale);
                return Ok(panel);
            }
        };
        let passwords = visit.passwords().await?;
        let Ok(classified) = Classified::new(&analysis, record, &passwords) else {
            panel.problem = tr(locale, keys::WEB_MIGRATE_PROBLEM_SOURCE, None);
            return Ok(panel);
        };
        let needs = Needs::of(&analysis, &classified, record);
        panel.nothing = needs.none();
        panel.passwords = needs
            .users()
            .iter()
            .enumerate()
            .map(|(index, user)| Password {
                stored: passwords.contains_key(user),
                error: shown
                    .passwords
                    .iter()
                    .find(|(name, _)| name == user)
                    .map_or_else(String::new, |(_, error)| error.clone()),
                user: user.clone(),
                field: format!("password-{index}"),
                index,
            })
            .collect();
        panel.components = needs
            .components()
            .iter()
            .map(|(name, count)| {
                let mut args = FluentArgs::new();
                args.set("count", u32::try_from(*count).unwrap_or(u32::MAX));
                Component {
                    checked: shown.components.as_ref().map_or_else(
                        || record.components().contains(name),
                        |checked| checked.contains(name),
                    ),
                    needed: tr(
                        locale,
                        keys::WEB_MIGRATE_INPUTS_COMPONENT_NEEDED,
                        Some(&args),
                    ),
                    name: name.clone(),
                }
            })
            .collect();
        panel.reconnect = needs.reconnect().then(|| {
            shown
                .reconnect
                .or_else(|| record.reconnect_url().map(str::to_owned))
                .unwrap_or_else(|| analysis.target().management_url.clone())
        });
        let (accepted, agreement_error) = shown
            .agreements
            .unwrap_or_else(|| (record.agreements().keys().cloned().collect(), String::new()));
        panel.agreements = needs
            .agreements()
            .iter()
            .map(|(name, text)| {
                let checked = accepted.iter().any(|known| known == name);
                Agreement {
                    name,
                    label: agreement_name(name, locale),
                    text: text.clone(),
                    error: if checked {
                        String::new()
                    } else {
                        agreement_error.clone()
                    },
                    checked,
                }
            })
            .collect();
        Ok(panel)
    }
}
