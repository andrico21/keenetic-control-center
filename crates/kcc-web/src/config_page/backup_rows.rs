//! One backup as the backups table shows it: when, which kind, why, and how long ago.

use core::time::Duration;
use std::time::SystemTime;

use fluent_bundle::FluentArgs;
use kcc_app::backups::BackupInfo;
use kcc_i18n::{bundle::tr, format, keys, locale::Locale};

use crate::table::{
    Direction, Sort,
    rows::{Row, SortKey},
};

/// The reason the change workflow gives its automatic backups.
const AUTOMATIC: &str = "pre-change";

/// The reason of a backup created on this page.
pub(crate) const MANUAL: &str = "manual";

/// The reason of an uploaded backup; a sanitized file name may follow after a hyphen.
pub(crate) const UPLOADED: &str = "upload";

/// One backup as the table shows it.
#[derive(Debug, Clone)]
pub(crate) struct BackupRow {
    /// File name in the store, the backup's id.
    name: String,
    /// Creation time, Unix seconds.
    created_at: u64,
    /// "Automatic", "Manual" or "Uploaded", localized.
    kind: String,
    /// Why it was made, localized when kcc made it.
    reason: String,
    /// Whether the reason is the stored text rather than a sentence.
    reason_raw: bool,
    /// Creation time as RFC 3339, for `<time datetime>`.
    created_iso: String,
    /// Creation time as `YYYY-MM-DD HH:MM UTC`, until the browser localizes it.
    created_text: String,
    /// How long ago it was made.
    age: String,
}

impl Row for BackupRow {
    const COLUMNS: &'static [&'static str] = &["created", "kind", "reason"];
    const DEFAULT: Sort = Sort::new("created", Direction::Descending);

    fn key(&self, column: &str) -> SortKey {
        match column {
            "kind" => SortKey::text(&self.kind),
            "reason" => SortKey::text(&self.reason),
            _ => SortKey::Number(self.created_at.into()),
        }
    }

    fn matches(&self, needle: &str) -> bool {
        [&self.name, &self.kind, &self.reason]
            .into_iter()
            .any(|field| field.to_lowercase().contains(needle))
    }
}

impl BackupRow {
    /// The row of `info` in `locale`, its age counted to `now`.
    pub(crate) fn new(info: BackupInfo, locale: Locale, now: u64) -> Self {
        let stored = info.reason.as_str();
        let upload = stored
            .strip_prefix(UPLOADED)
            .filter(|rest| rest.is_empty() || rest.starts_with('-'))
            .map(|rest| rest.trim_start_matches('-').to_owned());
        let (kind, reason, reason_raw) = match (stored, upload) {
            (AUTOMATIC, _) => (
                keys::WEB_CONFIG_KIND_AUTOMATIC,
                tr(locale, keys::WEB_CONFIG_REASON_CHANGE, None),
                false,
            ),
            (MANUAL, _) => (
                keys::WEB_CONFIG_KIND_MANUAL,
                tr(locale, keys::WEB_CONFIG_REASON_MANUAL, None),
                false,
            ),
            (_, Some(file)) if !file.is_empty() => (keys::WEB_CONFIG_KIND_UPLOADED, file, true),
            (_, Some(_)) => (
                keys::WEB_CONFIG_KIND_UPLOADED,
                tr(locale, keys::WEB_CONFIG_REASON_UPLOAD, None),
                false,
            ),
            (other, None) => (keys::WEB_CONFIG_KIND_MANUAL, other.to_owned(), true),
        };
        let (created_iso, created_text) = stamp(info.created_at);
        let mut args = FluentArgs::new();
        args.set(
            "value",
            format::duration(locale, now.saturating_sub(info.created_at)),
        );
        Self {
            name: info.name,
            created_at: info.created_at,
            kind: tr(locale, kind, None),
            reason,
            reason_raw,
            created_iso,
            created_text,
            age: tr(locale, keys::WEB_CONFIG_AGE, Some(&args)),
        }
    }

    /// File name in the store.
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    /// The kind, localized.
    pub(crate) fn kind(&self) -> &str {
        &self.kind
    }

    /// Why it was made.
    pub(crate) fn reason(&self) -> &str {
        &self.reason
    }

    /// Whether the reason is stored text, shown in the mono face.
    pub(crate) const fn reason_raw(&self) -> bool {
        self.reason_raw
    }

    /// Creation time as RFC 3339.
    pub(crate) fn created_iso(&self) -> &str {
        &self.created_iso
    }

    /// Creation time as `YYYY-MM-DD HH:MM UTC`.
    pub(crate) fn created_text(&self) -> &str {
        &self.created_text
    }

    /// How long ago it was made.
    pub(crate) fn age(&self) -> &str {
        &self.age
    }
}

/// Unix second `seconds` as RFC 3339 and as `YYYY-MM-DD HH:MM UTC`.
pub(crate) fn stamp(seconds: u64) -> (String, String) {
    let time = SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .unwrap_or(SystemTime::UNIX_EPOCH);
    let iso = humantime::format_rfc3339_seconds(time).to_string();
    let minutes = iso.get(..16).unwrap_or(&iso).replace('T', " ");
    (iso, format!("{minutes} UTC"))
}
