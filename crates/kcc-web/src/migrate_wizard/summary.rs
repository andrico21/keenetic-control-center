//! How a migration is named on its pages: the title, the source and the summary of what
//! it moves from where to where.

use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
};

use super::{kinds::Mode, record::Record};
use crate::{
    page::Shell,
    wizard::{flow::Flow as _, source::source_text},
};

/// The title of a wizard in `mode`.
pub(super) const fn title(mode: Mode) -> MessageKey {
    match mode {
        Mode::Migrate => keys::MIGRATE_TITLE,
        Mode::Restore => keys::WEB_MIGRATE_RESTORE_TITLE,
    }
}

/// Source and target of `record`, as far as chosen.
pub(super) fn summary(record: &Record, shell: &Shell) -> Vec<(String, String)> {
    let locale = shell.locale();
    let source = record.source().map(|source| {
        (
            tr(locale, keys::WEB_MIGRATE_SUMMARY_SOURCE, None),
            source_text(source, shell),
        )
    });
    let target = record.target().map(|target| {
        (
            tr(locale, keys::MIGRATE_TARGET, None),
            shell.router_name(target).to_owned(),
        )
    });
    source.into_iter().chain(target).collect()
}
