//! Step 1 of both wizards: where the configuration comes from (a router of the fleet, an
//! uploaded startup-config file, or a stored backup), how it is named, and the panel that
//! asks for it.
//!
//! A migration asks with the panel at `{PREFIX}/{id}/source`; a new preset
//! (`/ui/presets/new`) asks with the same panel, posted to its own route.

use askama::Template;
use fluent_bundle::FluentArgs;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};
use serde::{Deserialize, Serialize};

use super::services::Services;
use crate::{
    admin_shared::Timestamp,
    page::{Localize as _, Shell},
    page_kit::{
        context::fragment_shell,
        respond::{self, Answer},
    },
};

/// Where the source configuration came from; its text is sealed beside the record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum Source {
    /// A router of the fleet, read when the step was submitted.
    Router {
        /// Router profile id.
        router: String,
    },
    /// An uploaded startup-config file.
    File {
        /// The file name the browser sent, cleaned for display.
        name: String,
    },
    /// A stored backup of a router.
    Backup {
        /// Router profile id the backup belongs to.
        router: String,
        /// Backup file name.
        name: String,
    },
}

impl Source {
    /// The router whose scope the source needs, when it has one.
    pub(crate) fn router(&self) -> Option<&str> {
        match self {
            Self::Router { router } | Self::Backup { router, name: _ } => Some(router),
            Self::File { name: _ } => None,
        }
    }
}

/// How `source` is named in the summary and the migration list, in `shell`'s locale
/// and with the names of its fleet switcher.
pub(crate) fn source_text(source: &Source, shell: &Shell) -> String {
    let mut args = FluentArgs::new();
    let key = match source {
        Source::Router { router } => {
            args.set("router", shell.router_name(router).to_owned());
            keys::WEB_MIGRATE_SOURCE_IS_ROUTER
        }
        Source::File { name } => {
            args.set("name", name.clone());
            keys::WEB_MIGRATE_SOURCE_IS_FILE
        }
        Source::Backup { router, name } => {
            args.set("router", shell.router_name(router).to_owned());
            args.set("name", name.clone());
            keys::WEB_MIGRATE_SOURCE_IS_BACKUP
        }
    };
    tr(shell.locale(), key, Some(&args))
}

/// The step's panel.
#[derive(Template)]
#[template(path = "partials/migrate_source.html")]
pub(crate) struct Panel {
    /// Locale carrier.
    shell: Shell,
    /// Where the form posts.
    action: String,
    /// The panel's title and the sentence under it.
    words: (MessageKey, MessageKey),
    /// The chosen kind: `router`, `file` or `backup`.
    kind: &'static str,
    /// Routers the user may migrate from.
    routers: Vec<Choice>,
    /// Their stored backups, per router.
    groups: Vec<Group>,
    /// Field errors.
    errors: Errors,
}

localized!(Panel);

/// One option of a select.
struct Choice {
    /// The value sent.
    value: String,
    /// The text shown.
    label: String,
    /// Whether it is selected.
    selected: bool,
}

/// The backups of one router.
struct Group {
    /// What people read for the router: its display name, else its id.
    name: String,
    /// Its backups, newest first.
    backups: Vec<Choice>,
}

/// The form's field errors; empty when none.
#[derive(Default)]
struct Errors {
    /// The kind choice.
    kind: String,
    /// The router select.
    router: String,
    /// The file input.
    file: String,
    /// The backup select.
    backup: String,
}

/// Which field a refusal belongs to.
#[derive(Clone, Copy)]
pub(crate) enum Field {
    /// The kind choice.
    Kind,
    /// The router select.
    Router,
    /// The file input.
    File,
    /// The backup select.
    Backup,
}

impl Panel {
    /// The panel posting to `action` with the `(title, text)` words of a new preset.
    // cancel-safe: reads only.
    pub(crate) async fn for_preset(
        services: Services<'_>,
        action: String,
        words: (MessageKey, MessageKey),
    ) -> Self {
        let mut panel = Self::posting(services, action, None).await;
        panel.words = words;
        panel
    }

    /// The panel posting to `action`, with `source` chosen.
    // cancel-safe: reads only.
    pub(crate) async fn posting(
        services: Services<'_>,
        action: String,
        source: Option<&Source>,
    ) -> Self {
        let locale = services.user().locale();
        let chosen = |value: &str| match source {
            Some(Source::Router { router }) => router == value,
            Some(Source::Backup { router, name }) => format!("{router}/{name}") == value,
            Some(Source::File { name: _ }) | None => false,
        };
        let routers = match services.fleet().visible(services.user().role()).await {
            Ok(entries) => entries
                .into_iter()
                .map(|entry| {
                    (
                        entry.profile.id.clone(),
                        entry.profile.display_name().to_owned(),
                    )
                })
                .filter(|(router, _)| services.may_migrate(router))
                .collect::<Vec<_>>(),
            Err(error) => {
                tracing::warn!(%error, "migration source: routers could not be listed");
                Vec::new()
            }
        };
        let groups = routers
            .iter()
            .filter_map(|(router, name)| {
                let backups = services.fleet().workflow().backups().list(router).ok()?;
                (!backups.is_empty()).then(|| Group {
                    name: name.clone(),
                    backups: backups
                        .into_iter()
                        .map(|backup| {
                            let value = format!("{router}/{}", backup.name);
                            let mut args = FluentArgs::new();
                            args.set(
                                "value",
                                Timestamp::at(backup.created_at, locale)
                                    .map_or_else(String::new, |time| time.text().to_owned()),
                            );
                            args.set("name", backup.reason);
                            Choice {
                                selected: chosen(&value),
                                label: tr(
                                    locale,
                                    keys::WEB_MIGRATE_SOURCE_BACKUP_OPTION,
                                    Some(&args),
                                ),
                                value,
                            }
                        })
                        .collect(),
                })
            })
            .collect();
        Self {
            shell: fragment_shell(locale),
            action,
            words: (
                keys::WEB_MIGRATE_SOURCE_TITLE,
                keys::WEB_MIGRATE_SOURCE_TEXT,
            ),
            kind: match source {
                Some(Source::File { name: _ }) => "file",
                Some(Source::Backup { router: _, name: _ }) => "backup",
                Some(Source::Router { router: _ }) | None => "router",
            },
            routers: routers
                .into_iter()
                .map(|(router, name)| Choice {
                    selected: chosen(&router),
                    label: name,
                    value: router,
                })
                .collect(),
            groups,
            errors: Errors::default(),
        }
    }

    /// The panel with `message` beside `field`, the kind `kind` chosen.
    pub(crate) fn refusing(mut self, kind: &'static str, field: Field, message: String) -> Self {
        self.kind = kind;
        let slot = match field {
            Field::Kind => &mut self.errors.kind,
            Field::Router => &mut self.errors.router,
            Field::File => &mut self.errors.file,
            Field::Backup => &mut self.errors.backup,
        };
        *slot = message;
        self
    }
}

/// The panel refusing the submit with `message` beside `field`, as 422.
pub(crate) fn refuse(
    panel: Panel,
    kind: &'static str,
    field: Field,
    message: MessageKey,
    locale: Locale,
) -> Answer {
    let refused = panel.refusing(kind, field, tr(locale, message, None));
    respond::unprocessable(&refused).into()
}
