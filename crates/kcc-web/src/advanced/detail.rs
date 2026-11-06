//! The command detail of the explorer: what the catalog and the official manual say about
//! one command, its arguments, and its generated request form.

use fluent_bundle::FluentArgs;
use kcc_catalog::{Catalog, Command, CommandKind, Risk};
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};
use url::form_urlencoded::byte_serialize;

use super::{check::risk_key, form::Form, meta, types::ArgumentRow};
use crate::page_kit::{
    facts::RouterFacts,
    gate::{Controls, command_permissions},
};

/// One command in a result or group list.
#[derive(Debug, Clone)]
pub(crate) struct CommandLink {
    /// Space-separated path.
    path: String,
    /// The path as a URL query value.
    query: String,
    /// Kind label.
    kind: MessageKey,
}

/// Everything the detail panel shows.
pub(crate) struct Detail {
    /// Space-separated path.
    path: String,
    /// The path as a URL query value.
    query: String,
    /// Kind label.
    kind: MessageKey,
    /// Risk label.
    risk: MessageKey,
    /// Whether the command only reads.
    read_only: bool,
    /// Whether the command runs in the background.
    background: bool,
    /// Whether the `no` form exists.
    negatable: bool,
    /// Interface type from the manual.
    interface_type: Option<String>,
    /// First firmware line.
    since: Option<String>,
    /// CLI context.
    context: Option<String>,
    /// Models whose manuals list the command.
    models: Vec<String>,
    /// Localized model count.
    models_label: String,
    /// The manual page link and its localized label.
    manual: Option<(String, String)>,
    /// The router model's manual and its localized label.
    model_manual: Option<(String, String)>,
    /// Argument rows.
    arguments: Vec<ArgumentRow>,
    /// The generated form.
    form: Form,
    /// Whether and why not the command can run.
    runnable: Runnable,
}

/// Whether the explorer can run a command for the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Runnable {
    /// The user may run it.
    Yes,
    /// The user's role may only preview it.
    Forbidden,
    /// It runs in the background and the job service is missing.
    NoJobs,
}

/// What a detail depends on besides the command.
pub(crate) struct Scope<'call> {
    /// Router facts.
    facts: &'call RouterFacts,
    /// What the user may do on the router.
    controls: Controls,
    /// Whether background commands can run.
    jobs: bool,
    /// Page locale.
    locale: Locale,
}

impl<'call> Scope<'call> {
    /// A scope for a user with `controls` on the router of `facts`.
    pub(crate) const fn new(facts: &'call RouterFacts, controls: Controls, locale: Locale) -> Self {
        Self {
            facts,
            controls,
            jobs: false,
            locale,
        }
    }

    /// Records whether the job service is attached.
    pub(crate) const fn with_jobs(mut self, jobs: bool) -> Self {
        self.jobs = jobs;
        self
    }
}

/// The detail of `path`, when the router's catalog has it.
pub(crate) fn detail(scope: &Scope<'_>, path: &str) -> Option<Detail> {
    let catalog = scope.facts.catalog();
    let command = catalog.lookup(path)?;
    let schema = catalog.to_json_schema(path)?;
    let risk = catalog.risk(path).unwrap_or(Risk::Write);
    let background = catalog.is_background(path);
    let facts = meta::lookup(catalog.version(), path);
    let locale = scope.locale;
    let model_manual = scope
        .facts
        .hw_id()
        .filter(|model| command.models.contains(*model))
        .and_then(|model| {
            let link = facts?.model_link(model)?;
            let mut args = FluentArgs::new();
            args.set("model", model.to_owned());
            Some((
                link,
                tr(locale, keys::WEB_EXPLORER_MANUAL_MODEL, Some(&args)),
            ))
        });
    let manual = facts.and_then(|found| {
        let link = found.page_link()?;
        let mut args = FluentArgs::new();
        args.set(
            "page",
            found
                .page()
                .map_or_else(String::new, |page| page.to_string()),
        );
        Some((
            link,
            tr(locale, keys::WEB_EXPLORER_MANUAL_PAGE, Some(&args)),
        ))
    });
    let mut count = FluentArgs::new();
    count.set("count", command.models.len());
    let permitted = scope.controls.permits(command_permissions(risk));
    Some(Detail {
        path: path.to_owned(),
        query: encode(path),
        kind: kind_label(command.kind),
        risk: risk_key(risk),
        read_only: risk == Risk::Read,
        background,
        negatable: command.prefix_no,
        interface_type: facts
            .and_then(meta::CommandMeta::interface_type)
            .map(str::to_owned),
        since: facts.and_then(meta::CommandMeta::since).map(str::to_owned),
        context: facts
            .and_then(meta::CommandMeta::context)
            .map(str::to_owned),
        models: command.models.iter().cloned().collect(),
        models_label: tr(locale, keys::WEB_EXPLORER_MODELS_COUNT, Some(&count)),
        manual,
        model_manual,
        arguments: command
            .arguments
            .values()
            .map(|argument| ArgumentRow::new(argument, locale))
            .collect(),
        form: Form::build(&schema, locale),
        runnable: match (permitted, background && !scope.jobs) {
            (_, true) => Runnable::NoJobs,
            (true, false) => Runnable::Yes,
            (false, false) => Runnable::Forbidden,
        },
    })
}

/// The list entries of `commands`.
pub(crate) fn links<'catalog, I>(commands: I) -> Vec<CommandLink>
where
    I: IntoIterator<Item = &'catalog Command>,
{
    commands
        .into_iter()
        .map(|command| CommandLink {
            path: command.path.clone(),
            query: encode(&command.path),
            kind: kind_label(command.kind),
        })
        .collect()
}

/// The commands of `catalog` under the top-level word `prefix`.
pub(crate) fn group_commands<'catalog>(
    catalog: &'catalog Catalog,
    prefix: &str,
) -> Vec<&'catalog Command> {
    catalog
        .commands()
        .filter(|command| {
            command.path == prefix
                || command
                    .path
                    .strip_prefix(prefix)
                    .is_some_and(|rest| rest.starts_with(' '))
        })
        .collect()
}

/// `text` as a URL query value.
pub(crate) fn encode(text: &str) -> String {
    byte_serialize(text.as_bytes()).collect()
}

/// The label of a command kind.
const fn kind_label(kind: CommandKind) -> MessageKey {
    match kind {
        CommandKind::Show => keys::WEB_EXPLORER_KIND_SHOW,
        CommandKind::Action => keys::WEB_EXPLORER_KIND_ACTION,
        CommandKind::Setting | _ => keys::WEB_EXPLORER_KIND_SETTING,
    }
}

impl CommandLink {
    /// Space-separated path.
    pub(crate) fn path(&self) -> &str {
        &self.path
    }

    /// The path as a URL query value.
    pub(crate) fn query(&self) -> &str {
        &self.query
    }

    /// Kind label.
    pub(crate) const fn kind(&self) -> MessageKey {
        self.kind
    }
}

impl Detail {
    /// Space-separated path.
    pub(crate) fn path(&self) -> &str {
        &self.path
    }

    /// The path as a URL query value.
    pub(crate) fn query(&self) -> &str {
        &self.query
    }

    /// Kind label.
    pub(crate) const fn kind(&self) -> MessageKey {
        self.kind
    }

    /// Risk label.
    pub(crate) const fn risk(&self) -> MessageKey {
        self.risk
    }

    /// Whether the command runs in the background.
    pub(crate) const fn background(&self) -> bool {
        self.background
    }

    /// Whether the `no` form exists.
    pub(crate) const fn negatable(&self) -> bool {
        self.negatable
    }

    /// Interface type from the manual.
    pub(crate) fn interface_type(&self) -> Option<&str> {
        self.interface_type.as_deref()
    }

    /// First firmware line.
    pub(crate) fn since(&self) -> Option<&str> {
        self.since.as_deref()
    }

    /// CLI context.
    pub(crate) fn context(&self) -> Option<&str> {
        self.context.as_deref()
    }

    /// Models whose manuals list the command.
    pub(crate) fn models(&self) -> &[String] {
        &self.models
    }

    /// Localized model count.
    pub(crate) fn models_label(&self) -> &str {
        &self.models_label
    }

    /// The manual page link and its label.
    pub(crate) const fn manual(&self) -> Option<&(String, String)> {
        self.manual.as_ref()
    }

    /// The router model's manual and its label.
    pub(crate) const fn model_manual(&self) -> Option<&(String, String)> {
        self.model_manual.as_ref()
    }

    /// Argument rows.
    pub(crate) fn arguments(&self) -> &[ArgumentRow] {
        &self.arguments
    }

    /// The generated form.
    pub(crate) const fn form(&self) -> &Form {
        &self.form
    }

    /// Whether the user may run the command.
    pub(crate) const fn can_execute(&self) -> bool {
        matches!(self.runnable, Runnable::Yes)
    }

    /// Whether the command needs the missing job service.
    pub(crate) const fn jobs_missing(&self) -> bool {
        matches!(self.runnable, Runnable::NoJobs)
    }

    /// The execute button label: running a read or applying a change.
    pub(crate) const fn execute_label(&self) -> MessageKey {
        if self.read_only {
            keys::WEB_EXPLORER_RUN
        } else {
            keys::WEB_EXPLORER_EXECUTE
        }
    }
}
