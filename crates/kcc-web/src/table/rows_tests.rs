//! Unit tests of the typed table: filtering, sorting, pages and the kit's filter markup.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#![expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
use core::error::Error;

use askama::Template;
use kcc_i18n::{keys, locale::Locale};

use super::{Row, SortKey, Table, TableQuery};
use crate::{
    page::{Localize, Shell, Theme},
    table::{Direction, Sort, pager::PAGE_ROWS},
};

/// The kit's table filter and pager around one table.
#[derive(Template)]
#[template(
    ext = "html",
    source = r#"{%- import "partials/kit_macros.html" as kit -%}
{{ kit::filter(table, t(keys::WEB_KIT_TABLE_FILTER)) }}
{%- let pager = table.pager() %}
{%- include "partials/kit_pager.html" %}"#
)]
struct Filtered {
    /// Locale carrier.
    shell: Shell,
    /// The table.
    table: Table<Client>,
}

impl Localize for Filtered {
    fn shell(&self) -> &Shell {
        &self.shell
    }
}

/// A client row of the example table.
#[derive(Debug, Clone)]
struct Client {
    /// Name.
    name: String,
    /// Received bytes, when known.
    rx: Option<u64>,
}

impl Row for Client {
    const COLUMNS: &'static [&'static str] = &["name", "rx"];
    const DEFAULT: Sort = Sort::new("name", Direction::Ascending);

    fn key(&self, column: &str) -> SortKey {
        match column {
            "rx" => self
                .rx
                .map_or(SortKey::Missing, |bytes| SortKey::Number(bytes.into())),
            _ => SortKey::text(&self.name),
        }
    }

    fn matches(&self, needle: &str) -> bool {
        self.name.to_lowercase().contains(needle)
    }
}

/// `count` clients named `host-000` and up; every third has no counter.
fn clients(count: u64) -> Vec<Client> {
    (0..count)
        .map(|index| Client {
            name: format!("host-{index:03}"),
            rx: (!index.is_multiple_of(3)).then_some(index.saturating_mul(10)),
        })
        .collect()
}

/// A query from its parts.
fn query(filter: &str, sort: &str, dir: &str, page: &str) -> TableQuery {
    TableQuery {
        filter: Some(filter.to_owned()),
        sort: Some(sort.to_owned()),
        dir: Some(dir.to_owned()),
        page: Some(page.to_owned()),
    }
}

#[test]
fn tables_filter_sort_and_page_their_rows() {
    let table = Table::new(
        clients(120),
        &TableQuery::default(),
        "/ui/r/home/clients".to_owned(),
    );
    assert_eq!(table.rows().len(), PAGE_ROWS, "one page");
    assert_eq!((table.matched(), table.total()), (120, 120), "unfiltered");
    assert_eq!(
        table.rows().first().map(|row| row.name.as_str()),
        Some("host-000"),
        "default order"
    );
    assert_eq!(
        table.pager().next().as_deref(),
        Some("/ui/r/home/clients?sort=name&dir=asc&page=2"),
        "the next page keeps the sort"
    );
    let sorted = Table::new(clients(120), &query("", "rx", "desc", "1"), "/t".to_owned());
    assert_eq!(
        sorted.rows().first().and_then(|row| row.rx),
        None,
        "descending puts the missing values first"
    );
    let filtered = Table::new(
        clients(120),
        &query(" HOST-11 ", "rx", "asc", "1"),
        "/t".to_owned(),
    );
    let names: Vec<&str> = filtered
        .rows()
        .iter()
        .map(|row| row.name.as_str())
        .collect();
    assert_eq!(
        names,
        [
            "host-110", "host-112", "host-113", "host-115", "host-116", "host-118", "host-119",
            "host-111", "host-114", "host-117"
        ],
        "filtered without case, numbers first, missing last"
    );
    assert_eq!(filtered.filter(), "HOST-11", "trimmed filter");
    assert_eq!(
        filtered.header("name").href(),
        "/t?q=HOST-11&sort=name&dir=asc",
        "the sort header keeps the filter"
    );
    let beyond = Table::new(clients(10), &query("", "name", "asc", "9"), "/t".to_owned());
    assert_eq!(
        beyond.rows().len(),
        10,
        "a page past the end shows the last"
    );
    assert!(!beyond.pager().multiple(), "one page");
}

#[test]
fn the_filter_keeps_the_sort_and_the_pager_keeps_both() -> Result<(), Box<dyn Error>> {
    let html = Filtered {
        shell: Shell::new(Locale::En, Theme::System),
        table: Table::new(
            clients(300),
            &query("host", "rx", "desc", "2"),
            "/ui/r/home/clients".to_owned(),
        ),
    }
    .render()?;
    for expected in [
        "<form class=\"table-filter\" role=\"search\" method=\"get\" action=\"/ui/r/home/clients\">",
        "name=\"q\" type=\"search\" value=\"host\"",
        "<input type=\"hidden\" name=\"sort\" value=\"rx\">",
        "<input type=\"hidden\" name=\"dir\" value=\"desc\">",
        "<a class=\"button button--ghost\" href=\"/ui/r/home/clients\">Clear</a>",
        "href=\"/ui/r/home/clients?q=host&#38;sort=rx&#38;dir=desc&#38;page=1\"",
        "href=\"/ui/r/home/clients?q=host&#38;sort=rx&#38;dir=desc&#38;page=3\"",
        "Page 2 of 6",
    ] {
        assert!(html.contains(expected), "missing {expected} in {html}");
    }
    Ok(())
}
