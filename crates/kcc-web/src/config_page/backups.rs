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
    page_kit::{
        context::fragment_shell, gate::Controls, read_failure::ReadProblem, request::with_query,
    },
    table::{
        acts::{Act, MenuItem},
        cells::{Cell, Layout},
        head::Head,
        piece::Piece,
        rows::{Table, TableQuery},
        view::TableView,
    },
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
    problem: Option<ReadProblem>,
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
fragment!(BackupsRegion);

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
            problem: Some(keys::WEB_CONFIG_NO_STORE.into()),
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
            Err(StoreError::Missing | StoreError::Failed) => {
                region.problem = Some(keys::WEB_CONFIG_STORE_FAILED.into());
                return region;
            }
        };
        let now = visit.now();
        region.sizes = listed
            .iter()
            .map(|info| (info.name.clone(), format::bytes(locale, info.size)))
            .collect();
        let rows: Vec<BackupRow> = listed
            .into_iter()
            .map(|info| BackupRow::new(info, locale, now))
            .collect();
        region.compare = CompareForm::new(locale, router, &rows);
        let table = Table::new(rows, query, format!("/ui/r/{router}/config"));
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

    /// The backups table, or the note in its place; none when the backups could not be
    /// listed.
    fn backups(&self) -> Option<TableView> {
        let table = self.table.as_ref()?;
        let locale = self.shell.locale();
        let said = |key: MessageKey| tr(locale, key, None);
        let empty = keys::WEB_CONFIG_BACKUPS_EMPTY;
        let mut view =
            TableView::filtered("table backups-table", table, (locale, empty)).noted("panel__note");
        for (column, key) in [
            ("created", keys::WEB_CONFIG_CREATED),
            ("kind", keys::WEB_CONFIG_KIND),
            ("reason", keys::WEB_CONFIG_REASON),
        ] {
            view = view.head(Head::sorted(said(key), table.header(column)));
        }
        view = view
            .head(Head::plain(said(keys::WEB_CONFIG_SIZE)).with_class("numeric"))
            .head(Head::hidden(said(keys::WEB_CONFIG_ACTIONS)));
        for (index, row) in table.rows().iter().enumerate() {
            let item = index.saturating_add(1);
            let created = Piece::element("time", row.created_text().to_owned())
                .attr("class", "backups-table__time".to_owned())
                .attr("datetime", row.created_iso().to_owned())
                .flagged("data-kcc-time");
            let age = Piece::span("backups-table__age", row.age().to_owned());
            let reason = if row.reason_raw() {
                Piece::span("mono", row.reason().to_owned())
            } else {
                Piece::text(row.reason().to_owned())
            };
            view = view.row(vec![
                Cell::of(vec![created, age])
                    .attr("id", format!("backup-{item}"))
                    .head(),
                Cell::text(row.kind().to_owned()),
                Cell::of(vec![reason]),
                Cell::text(self.size(row).to_owned()).class("numeric"),
                Cell::acts(
                    Layout::Block,
                    self.row_acts(row, item),
                    format!("backup-{item}"),
                )
                .class("backups-actions"),
            ]);
        }
        Some(view)
    }

    /// The actions of `row`, row `item`: the download, and the menu of the others.
    fn row_acts(&self, row: &BackupRow, item: usize) -> Vec<Act> {
        let locale = self.shell.locale();
        let said = |key: MessageKey| tr(locale, key, None);
        let download = if self.may_reveal() {
            Act::download(locale, keys::WEB_CONFIG_DOWNLOAD, self.download_full(row))
        } else {
            let href = self.download_redacted(row);
            Act::download(locale, keys::WEB_CONFIG_DOWNLOAD_REDACTED, href)
        };
        let mut items = Vec::new();
        if self.may_reveal() {
            let label = said(keys::WEB_CONFIG_DOWNLOAD_REDACTED);
            items.push(MenuItem::download(label, self.download_redacted(row)));
        }
        let compare = said(keys::WEB_CONFIG_COMPARE_RUNNING);
        items.push(MenuItem::link(compare, self.compare_running(row)));
        if self.may_use_wizard() {
            let label = said(keys::WEB_CONFIG_RESTORE_WIZARD);
            items.push(MenuItem::link(label, self.wizard(row)));
        }
        if self.may_restore_raw() {
            let label = said(keys::WEB_CONFIG_RAW_RESTORE);
            items.push(MenuItem::hides(label, self.act("raw-restore", row)).danger());
        }
        if self.may_delete() {
            let label = said(keys::COMMON_DELETE);
            items.push(MenuItem::hides(label, self.act("delete", row)).danger());
        }
        let menu = (format!("backup-menu-{item}"), "menu lan-menu backups-menu");
        vec![
            download,
            Act::menu_of(said(keys::WEB_CONFIG_ACTIONS), menu, items),
        ]
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
