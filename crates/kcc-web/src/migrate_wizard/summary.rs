//! How a migration is named on its pages: the title, the source and the summary of what
//! it moves from where to where.

use fluent_bundle::FluentArgs;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};

use super::{
    kinds::{Mode, Source},
    record::Record,
};
use crate::wizard::flow::Flow as _;

/// The title of a wizard in `mode`.
pub(super) const fn title(mode: Mode) -> MessageKey {
    match mode {
        Mode::Migrate => keys::MIGRATE_TITLE,
        Mode::Restore => keys::WEB_MIGRATE_RESTORE_TITLE,
    }
}

/// How `source` is named in the summary and the migration list.
pub(crate) fn source_text(source: &Source, locale: Locale) -> String {
    let mut args = FluentArgs::new();
    let key = match source {
        Source::Router { router } => {
            args.set("router", router.clone());
            keys::WEB_MIGRATE_SOURCE_IS_ROUTER
        }
        Source::File { name } => {
            args.set("name", name.clone());
            keys::WEB_MIGRATE_SOURCE_IS_FILE
        }
        Source::Backup { router, name } => {
            args.set("router", router.clone());
            args.set("name", name.clone());
            keys::WEB_MIGRATE_SOURCE_IS_BACKUP
        }
    };
    tr(locale, key, Some(&args))
}

/// Source and target of `record`, as far as chosen.
pub(super) fn summary(record: &Record, locale: Locale) -> Vec<(String, String)> {
    let source = record.source().map(|source| {
        (
            tr(locale, keys::WEB_MIGRATE_SUMMARY_SOURCE, None),
            source_text(source, locale),
        )
    });
    let target = record
        .target()
        .map(|target| (tr(locale, keys::MIGRATE_TARGET, None), target.to_owned()));
    source.into_iter().chain(target).collect()
}
