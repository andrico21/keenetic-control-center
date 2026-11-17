//! The filter links above a wizard's review: every setting, then each fate with settings,
//! with their counts.

use core::iter;

use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};

/// One filter link.
pub(crate) struct Filter {
    /// The link.
    href: String,
    /// "Conflicts (2)".
    label: String,
    /// Whether it is shown.
    current: bool,
}

impl Filter {
    /// The link.
    pub(crate) fn href(&self) -> &str {
        &self.href
    }

    /// "Conflicts (2)".
    pub(crate) fn label(&self) -> &str {
        &self.label
    }

    /// Whether it is shown.
    pub(crate) const fn current(&self) -> bool {
        self.current
    }
}

/// The links over rows whose fates are `rows` (each row's fate slug), under the review at
/// `base` in `locale`: "all", then each of `fates` (slug, label and whether it is shown)
/// that has rows.
pub(crate) fn filters<I>(rows: &[&str], fates: I, (base, locale): (&str, Locale)) -> Vec<Filter>
where
    I: IntoIterator<Item = (&'static str, MessageKey, bool)>,
{
    let listed = fates.into_iter().collect::<Vec<_>>();
    let shown = listed.iter().any(|&(_, _, current)| current);
    let each = listed
        .into_iter()
        .filter_map(|(slug, label, current)| {
            let count = rows.iter().filter(|fate| **fate == slug).count();
            (count > 0).then(|| Filter {
                href: format!("{base}?show={slug}"),
                label: format!("{} ({count})", tr(locale, label, None)),
                current,
            })
        })
        .collect::<Vec<_>>();
    let all = Filter {
        href: base.to_owned(),
        label: format!(
            "{} ({})",
            tr(locale, keys::WEB_MIGRATE_FATE_ALL, None),
            rows.len()
        ),
        current: !shown,
    };
    iter::once(all).chain(each).collect()
}
