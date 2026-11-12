//! The flow the DNS and VPN requests share: the page request, the viewer a region is
//! built for, and running a planned change, answered with its outcome and the region
//! read back.

use axum::http::HeaderMap;
use kcc_app::workflow::CliChangeRequest;
use kcc_catalog::Risk;
use kcc_domain::{OperationDescriptor, RouterCtx};
use kcc_i18n::{bundle::tr, locale::Locale};
use serde_json::{Map, Value};
use url::Url;

use super::{
    cells::Act,
    region::Region,
    screen::{Answered, Tab},
};
use crate::{
    WebState,
    authz::CurrentUser,
    page::Shell,
    page_kit::{
        action::Action,
        change::Change,
        context::{self, Caller, Refusal},
        family::Family,
        gate::Controls,
    },
    table::rows::TableQuery,
};

/// A page request: the services, the signed-in user, the router and the table query.
pub(crate) struct Visit<'call> {
    /// Web services.
    state: &'call WebState,
    /// The signed-in user.
    user: &'call CurrentUser,
    /// Router profile id.
    router: &'call str,
    /// The table's filter, sort and page.
    query: TableQuery,
}

impl<'call> Visit<'call> {
    /// `user` opening a page of `router`.
    pub(crate) fn new(
        state: &'call WebState,
        user: &'call CurrentUser,
        router: &'call str,
    ) -> Self {
        Self {
            state,
            user,
            router,
            query: TableQuery::default(),
        }
    }

    /// The table shows what `query` asks for.
    pub(crate) fn with_query(mut self, query: TableQuery) -> Self {
        self.query = query;
        self
    }

    /// Router profile id.
    pub(crate) const fn router(&self) -> &'call str {
        self.router
    }

    /// The user's locale.
    pub(crate) const fn locale(&self) -> Locale {
        self.user.locale()
    }

    /// The full-page shell of `caller` for a page of `tab`, the router selected.
    // cancel-safe: reads only.
    pub(crate) async fn shell(&self, caller: Caller<'_>, tab: Tab) -> Shell {
        caller
            .shell(self.state, tab.section(), Some(self.router))
            .await
    }

    /// Opens the router for a page of `operations`: its domain context and the viewer.
    ///
    /// # Errors
    ///
    /// Returns the refusal of a router the user may not see, or the localized reason the
    /// router cannot be read now.
    // cancel-safe: reads only.
    pub(crate) async fn open(
        self,
        operations: &'static [OperationDescriptor],
    ) -> Result<(RouterCtx, Viewer), Closed> {
        let target = context::target(self.state, self.user, self.router)
            .await
            .map_err(Closed::Refused)?;
        let locale = self.locale();
        match target.context(self.state).await {
            Ok((facts, ctx)) => {
                let controls = Controls::new(self.user.role(), self.router)
                    .with_operations(operations, Some(facts.catalog()));
                let viewer = Viewer::new(self.router, locale, controls).with_query(self.query);
                Ok((ctx, viewer))
            }
            Err(error) => Err(Closed::Unreadable(tr(
                locale,
                error.message(Family::Changes),
                None,
            ))),
        }
    }
}

/// Why a page cannot show its router.
pub(crate) enum Closed {
    /// The user may not see the router: 404, 403 or 500.
    Refused(Refusal),
    /// The router cannot be read now; the localized reason.
    Unreadable(String),
}

/// Who views a region: the router, the locale, what the role may change and the table
/// query.
#[derive(Debug, Clone)]
pub(crate) struct Viewer {
    /// Router profile id.
    router: String,
    /// The viewer's locale.
    locale: Locale,
    /// What the role may change on the router.
    controls: Controls,
    /// The table's filter, sort and page.
    query: TableQuery,
}

impl Viewer {
    /// A viewer of `router` in `locale`, who may use `controls`.
    pub(crate) fn new(router: &str, locale: Locale, controls: Controls) -> Self {
        Self {
            router: router.to_owned(),
            locale,
            controls,
            query: TableQuery::default(),
        }
    }

    /// The table shows what `query` asks for.
    pub(crate) fn with_query(mut self, query: TableQuery) -> Self {
        self.query = query;
        self
    }

    /// The viewer's locale.
    pub(crate) const fn locale(&self) -> Locale {
        self.locale
    }

    /// Whether the role may run the operation `name`.
    pub(crate) fn allows(&self, name: &str) -> bool {
        self.controls.allows(name)
    }

    /// The table query.
    pub(crate) const fn query(&self) -> &TableQuery {
        &self.query
    }

    /// The page `path` of the router, such as `dns/records`.
    pub(crate) fn href(&self, path: &str) -> String {
        format!("/ui/r/{}/{path}", self.router)
    }
}

/// The table query of the page the browser shows, from htmx's `HX-Current-URL`, so a
/// region read back after a change keeps its filter, sort and page.
pub(crate) fn shown_query(headers: &HeaderMap) -> TableQuery {
    let pairs: Map<String, Value> = headers
        .get("hx-current-url")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| Url::parse(value).ok())
        .map(|url| {
            url.query_pairs()
                .filter(|(name, _)| matches!(name.as_ref(), "q" | "sort" | "dir" | "page"))
                .map(|(name, value)| (name.into_owned(), Value::String(value.into_owned())))
                .collect()
        })
        .unwrap_or_default();
    serde_json::from_value(Value::Object(pairs)).unwrap_or_default()
}

/// Runs `request` for `action` and answers with its outcome; after a success the region
/// and its page actions are read back with `read_back`.
// NOT cancel-safe: see `Action::run`.
pub(crate) async fn apply<F>(
    action: Action<'_>,
    request: CliChangeRequest,
    risk: Risk,
    read_back: F,
) -> Answered
where
    F: AsyncFnOnce() -> (Region, Vec<Act>),
{
    let locale = action.locale();
    let outcome = action.run(risk, Change::Cli(request)).await;
    let refreshed = if outcome.succeeded() {
        Some(read_back().await)
    } else {
        None
    };
    Answered::new(outcome, locale).refreshed(refreshed)
}
