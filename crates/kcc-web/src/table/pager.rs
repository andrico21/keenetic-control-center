//! One page of a long table, with links to its neighbours.
//!
//! Tables show [`PAGE_ROWS`] rows a page. [`Pager::paginate`] cuts the requested page out
//! of the rows and keeps the table's other query parameters (filter, sort) in the links to
//! the previous and next page.

use axum::http::HeaderMap;
use fluent_bundle::FluentArgs;
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use url::{Url, form_urlencoded};

/// Rows per table page.
pub const PAGE_ROWS: usize = 50;

/// One page of a table, with links to its neighbours.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Pager {
    /// Shown page, from 1.
    current: usize,
    /// Number of pages, at least 1.
    total: usize,
    /// Path of the table's page.
    path: String,
    /// Query parameters other than `page`, kept in the links.
    query: Vec<(String, String)>,
}

impl Pager {
    /// Cuts the `requested` page (clamped to the last) out of `rows`; the links go to
    /// `path` with the `query` parameters kept.
    #[inline]
    #[must_use]
    pub fn paginate<T>(
        rows: Vec<T>,
        requested: usize,
        path: String,
        query: Vec<(String, String)>,
    ) -> (Vec<T>, Self) {
        let total = rows.len().div_ceil(PAGE_ROWS).max(1);
        let current = requested.clamp(1, total);
        let skip = current.saturating_sub(1).saturating_mul(PAGE_ROWS);
        let page = rows.into_iter().skip(skip).take(PAGE_ROWS).collect();
        (
            page,
            Self {
                current,
                total,
                path,
                query,
            },
        )
    }

    /// Whether the table has more than one page.
    #[inline]
    #[must_use]
    pub const fn multiple(&self) -> bool {
        self.total > 1
    }

    /// The previous page's link.
    #[inline]
    #[must_use]
    pub fn previous(&self) -> Option<String> {
        (self.current > 1).then(|| self.href(self.current.saturating_sub(1)))
    }

    /// The next page's link.
    #[inline]
    #[must_use]
    pub fn next(&self) -> Option<String> {
        (self.current < self.total).then(|| self.href(self.current.saturating_add(1)))
    }

    /// "Page 2 of 3" in `locale`.
    #[inline]
    #[must_use]
    pub fn status(&self, locale: Locale) -> String {
        let mut args = FluentArgs::new();
        args.set("current", self.current);
        args.set("total", self.total);
        tr(locale, keys::WEB_ADMIN_PAGE_STATUS, Some(&args))
    }

    /// The link to `page` with the other query parameters.
    fn href(&self, page: usize) -> String {
        let mut query = form_urlencoded::Serializer::new(String::new());
        for (name, value) in &self.query {
            let _: &mut form_urlencoded::Serializer<'_, String> = query.append_pair(name, value);
        }
        let _: &mut form_urlencoded::Serializer<'_, String> =
            query.append_pair("page", &page.to_string());
        format!("{}?{}", self.path, query.finish())
    }
}

/// The page number the browser shows: `page` from htmx's `HX-Current-URL`, else 1, so a
/// table refreshed after a change stays on its page.
#[inline]
#[must_use]
pub fn shown_page(headers: &HeaderMap) -> usize {
    headers
        .get("hx-current-url")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| Url::parse(value).ok())
        .and_then(|url| {
            url.query_pairs()
                .find_map(|(name, value)| (name == "page").then(|| value.parse().ok()))
                .flatten()
        })
        .unwrap_or(1)
}
