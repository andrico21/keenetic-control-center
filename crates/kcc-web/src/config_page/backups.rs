//! The backups region (`#config-backups`) of the configuration page.
//!
//! The retention `kcc.toml` sets, Create and Upload, the table of backups (newest first,
//! filtered, sorted, 50 a page) with each row's actions, and the form comparing two
//! configurations.

use alloc::collections::BTreeMap;
use core::time::Duration;

use askama::Template;
use fluent_bundle::FluentArgs;
use kcc_app::permissions::Permission;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    format, keys,
    locale::Locale,
};

use super::{
    backup_rows::BackupRow,
    compare_view::CompareForm,
    page::Visit,
    restore::{WIZARD_SERVED, migrate_restore_url},
    store::{self, StoreError},
};
use crate::{
    page::{Localize as _, Shell},
    page_kit::{context::fragment_shell, gate::Controls},
    system_pages::shared::with_query,
    table::rows::{Table, TableQuery},
};

/// The backups region.
#[derive(Template)]
#[template(path = "partials/config_backups.html")]
pub(crate) struct BackupsRegion {
    /// Locale carrier.
    shell: Shell,
    /// Router profile id.
    router: String,
    /// The table; `None` when the backups could not be listed.
    table: Option<Table<BackupRow>>,
    /// Why the backups could not be listed.
    problem: Option<MessageKey>,
    /// Size of each shown backup, as people read it.
    sizes: BTreeMap<String, String>,
    /// The retention, as a sentence.
    retention: String,
    /// The form comparing two configurations.
    compare: CompareForm,
    /// What the role may do on the router.
    controls: Controls,
    /// Whether the region replaces the page's out of band.
    oob: bool,
}

localized!(BackupsRegion);

impl BackupsRegion {
    /// The region of `visit`, the table as `query` asks.
    // cancel-safe: reads only.
    pub(crate) async fn read(visit: Visit<'_>, query: &TableQuery) -> Self {
        let (user, router) = (visit.user(), visit.router());
        let locale = user.locale();
        let controls = Controls::new(user.role(), router);
        let mut region = Self {
            shell: fragment_shell(locale),
            router: router.to_owned(),
            table: None,
            problem: Some(keys::WEB_CONFIG_NO_STORE),
            sizes: BTreeMap::new(),
            retention: String::new(),
            compare: CompareForm::new(locale, router, &[]),
            controls,
            oob: false,
        };
        let Some(services) = visit.backups() else {
            return region;
        };
        region.retention = retention(
            locale,
            services.retention().keep_last,
            services.retention().max_age,
        );
        let listed = match store::list(services, router).await {
            Ok(found) => found,
            Err(StoreError::Missing | StoreError::Taken | StoreError::Failed) => {
                region.problem = Some(keys::WEB_CONFIG_STORE_FAILED);
                return region;
            }
        };
        let now = visit.now();
        let rows: Vec<BackupRow> = listed
            .into_iter()
            .map(|info| BackupRow::new(info, locale, now))
            .collect();
        region.compare = CompareForm::new(locale, router, &rows);
        let table = Table::new(rows, query, format!("/ui/r/{router}/config"));
        let names = table
            .rows()
            .iter()
            .map(|row| row.name().to_owned())
            .collect();
        region.sizes = store::sizes(services, router, names)
            .await
            .into_iter()
            .map(|(name, size)| (name, format::bytes(locale, size)))
            .collect();
        region.table = Some(table);
        region.problem = None;
        region
    }

    /// The region for replacing the page's out of band.
    pub(crate) const fn out_of_band(mut self) -> Self {
        self.oob = true;
        self
    }

    /// Whether the role may create and upload backups (`Write`).
    fn may_create(&self) -> bool {
        self.controls.holds(Permission::Write)
    }

    /// Whether the role may delete backups (`Destructive`).
    fn may_delete(&self) -> bool {
        self.controls.holds(Permission::Destructive)
    }

    /// Whether the role may download backups with their secrets (`RevealSecrets`).
    fn may_reveal(&self) -> bool {
        self.controls.holds(Permission::RevealSecrets)
    }

    /// Whether the role may restore through the migration wizard (`Migrate`), once this
    /// build serves it.
    fn may_use_wizard(&self) -> bool {
        WIZARD_SERVED && self.controls.holds(Permission::Migrate)
    }

    /// Whether the role holds `Migrate` while this build has no migration wizard yet.
    fn wizard_missing(&self) -> bool {
        !WIZARD_SERVED && self.controls.holds(Permission::Migrate)
    }

    /// Whether the role may restore raw (`Destructive` and `Migrate`).
    fn may_restore_raw(&self) -> bool {
        self.controls
            .permits(&[Permission::Destructive, Permission::Migrate])
    }

    /// The size of `row`, or empty when it could not be read.
    fn size(&self, row: &BackupRow) -> &str {
        self.sizes.get(row.name()).map_or("", String::as_str)
    }

    /// The endpoint of the backup action `action` on `row`.
    fn act(&self, action: &str, row: &BackupRow) -> String {
        with_query(
            &format!("/ui/r/{}/config/backups/{action}", self.router),
            &[("name", row.name())],
        )
    }

    /// The download of `row` as stored, with its secrets.
    fn download_full(&self, row: &BackupRow) -> String {
        with_query(
            &format!("/ui/r/{}/config/backups/download", self.router),
            &[("name", row.name()), ("full", "yes")],
        )
    }

    /// The download of `row` without its secrets.
    fn download_redacted(&self, row: &BackupRow) -> String {
        with_query(
            &format!("/ui/r/{}/config/backups/download", self.router),
            &[("name", row.name())],
        )
    }

    /// The comparison of `row` with the running configuration.
    fn compare_running(&self, row: &BackupRow) -> String {
        with_query(
            &format!("/ui/r/{}/config/diff", self.router),
            &[("from", row.name()), ("to", "running")],
        )
    }

    /// The migration wizard restoring `row` onto this router.
    fn wizard(&self, row: &BackupRow) -> String {
        migrate_restore_url(&self.router, row.name())
    }
}

/// The retention sentence: at most `keep` backups per router, none older than `max_age`.
fn retention(locale: Locale, keep: u32, max_age: Duration) -> String {
    let mut args = FluentArgs::new();
    args.set("count", keep);
    args.set("value", format::duration(locale, max_age.as_secs()));
    tr(locale, keys::WEB_CONFIG_RETENTION, Some(&args))
}
