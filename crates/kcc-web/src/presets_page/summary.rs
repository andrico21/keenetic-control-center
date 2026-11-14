//! How a preset run is named on its pages: the title, its settings and the summary of
//! what it applies where.

use core::iter;

use fluent_bundle::FluentArgs;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};

use super::{record::Record, steps::Origin};
use crate::wizard::flow::Flow as _;

/// The title of a run of `origin`.
pub(super) const fn title(origin: &Origin) -> MessageKey {
    match origin {
        Origin::Preset { id: _, name: _ } => keys::WEB_PRESETS_WIZARD_APPLY,
        Origin::Copy => keys::WEB_PRESETS_WIZARD_COPY,
    }
}

/// What the run's settings are called: the preset's name, or the copy's source.
pub(super) fn settings_text(record: &Record, locale: Locale) -> String {
    match (record.origin(), record.source_router()) {
        (Origin::Preset { id: _, name }, _) => name.clone(),
        (Origin::Copy, Some(router)) => {
            let mut args = FluentArgs::new();
            args.set("router", router.to_owned());
            tr(locale, keys::WEB_PRESETS_RUN_COPY, Some(&args))
        }
        (Origin::Copy, None) => tr(locale, keys::WEB_PRESETS_RUN_COPY_NEW, None),
    }
}

/// The settings and the target of `record`, as far as chosen.
pub(super) fn summary(record: &Record, locale: Locale) -> Vec<(String, String)> {
    let settings = (
        tr(locale, keys::WEB_PRESETS_SUMMARY_SETTINGS, None),
        settings_text(record, locale),
    );
    let target = record
        .target()
        .map(|target| (tr(locale, keys::MIGRATE_TARGET, None), target.to_owned()));
    iter::once(settings).chain(target).collect()
}
