//! What the system pages share: opening a page on its router, answering a change with
//! its outcome and the region read back, and the query strings their actions carry.

use askama::Template;
use axum::{
    http::{HeaderMap, StatusCode},
    response::{IntoResponse as _, Response},
};
use kcc_domain::RouterCtx;
use kcc_i18n::{bundle::MessageKey, keys, locale::Locale};
use serde_json::{Map, Value};
use url::{Url, form_urlencoded};

use crate::{
    WebState,
    authz::{CurrentSession, CurrentUser},
    errors::{self, Kind},
    nav::Section,
    page::{Localize as _, Shell},
    page_kit::{
        context::{self, Caller, fragment_shell},
        facts::RouterFacts,
        family::Family,
        outcome::{Outcome, with_status},
        respond::{self, Answer},
    },
    table::rows::TableQuery,
};

/// The router a system page reads: its catalog facts and the domain context, or why the
/// router cannot be read now.
pub(crate) type Reading = Result<(RouterFacts, RouterCtx), MessageKey>;

/// Who opens a page: the request headers, the session and the signed-in user.
#[derive(Clone, Copy)]
pub(crate) struct Visit<'request> {
    /// Request headers, for the theme cookie.
    headers: &'request HeaderMap,
    /// Session, for the CSRF token.
    current: &'request CurrentSession,
    /// Signed-in user.
    user: &'request CurrentUser,
}

impl<'request> Visit<'request> {
    /// The visit of one request.
    pub(crate) const fn new(
        headers: &'request HeaderMap,
        current: &'request CurrentSession,
        user: &'request CurrentUser,
    ) -> Self {
        Self {
            headers,
            current,
            user,
        }
    }

    /// Opens a system page on `router`: the full shell with the router selected and the
    /// System section current, then the router's facts and domain context.
    ///
    /// # Errors
    ///
    /// The error page when the router is unknown, outside the role's scope or the fleet
    /// is not configured.
    // cancel-safe: reads only.
    pub(crate) async fn open(
        self,
        state: &WebState,
        router: &str,
    ) -> Result<(Shell, Reading), Answer> {
        let shell = Caller::new(self.headers, self.current, self.user)
            .shell(state, Section::System, Some(router))
            .await;
        let target = match context::target(state, self.user, router).await {
            Ok(found) => found,
            Err(refusal) => return Err(refusal.page(shell).into()),
        };
        let reading = target
            .context(state)
            .await
            .map_err(|error| error.message(Family::Changes));
        Ok((shell, reading))
    }
}

/// The answer to a change: its outcome, then the page's region read back.
#[derive(Template)]
#[template(path = "partials/system_result.html")]
struct ResultView {
    /// Locale carrier.
    shell: Shell,
    /// The outcome.
    outcome: Outcome,
    /// The region read back, sent out of band after a success.
    refreshed: Option<String>,
}

localized!(ResultView);

/// The answer to a change: the outcome in the page's outcome region, the `refreshed`
/// region out of band, the shared dialog closed.
pub(crate) fn answer(outcome: Outcome, refreshed: Option<String>, locale: Locale) -> Response {
    let status = outcome.status();
    let view = ResultView {
        shell: fragment_shell(locale),
        outcome,
        refreshed,
    };
    respond::close_dialog(with_status(errors::render(&view), status))
}

/// `region` rendered for sending out of band; a failed render is logged and leaves the
/// page as it is.
pub(crate) fn rendered<T>(region: &T) -> Option<String>
where
    T: Template,
{
    match region.render() {
        Ok(html) => Some(html),
        Err(error) => {
            tracing::error!(%error, "system page region failed to render");
            None
        }
    }
}

/// The table query of the page the browser shows, from htmx's `HX-Current-URL`, so a
/// table refreshed after a change keeps its filter, sort and page.
pub(crate) fn shown_query(headers: &HeaderMap) -> TableQuery {
    let fields: Map<String, Value> = headers
        .get("hx-current-url")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| Url::parse(value).ok())
        .map(|url| {
            url.query_pairs()
                .map(|(name, value)| (name.into_owned(), Value::String(value.into_owned())))
                .collect()
        })
        .unwrap_or_default();
    serde_json::from_value(Value::Object(fields)).unwrap_or_default()
}

/// `path` with `pairs` as its query string; the values are names and choices, never
/// secrets.
pub(crate) fn with_query(path: &str, pairs: &[(&str, &str)]) -> String {
    let mut query = form_urlencoded::Serializer::new(String::new());
    for (name, value) in pairs {
        let _: &mut form_urlencoded::Serializer<'_, String> = query.append_pair(name, value);
    }
    format!("{path}?{}", query.finish())
}

/// The pairs of a request's query string, then those of its form body.
pub(crate) fn merged(query: Option<&str>, form: Vec<(String, String)>) -> Vec<(String, String)> {
    let mut pairs: Vec<(String, String)> = query
        .map(|text| {
            form_urlencoded::parse(text.as_bytes())
                .into_owned()
                .collect()
        })
        .unwrap_or_default();
    pairs.extend(form);
    pairs
}

/// The last value of `name` in `pairs`, trimmed.
pub(crate) fn value<'pairs>(pairs: &'pairs [(String, String)], name: &str) -> Option<&'pairs str> {
    pairs
        .iter()
        .rev()
        .find(|(key, _)| key == name)
        .map(|(_, found)| found.trim())
}

/// Every value of `name` in `pairs`, trimmed, in order.
pub(crate) fn values<'pairs>(pairs: &'pairs [(String, String)], name: &str) -> Vec<&'pairs str> {
    pairs
        .iter()
        .filter(|(key, _)| key == name)
        .map(|(_, found)| found.trim())
        .collect()
}

/// The 403 answer of an action the role may not take at the risk it would run at.
pub(crate) fn forbidden(locale: Locale) -> Answer {
    errors::response(Kind::Forbidden, fragment_shell(locale)).into()
}

/// The 404 answer of an object the page does not have.
pub(crate) fn missing() -> Answer {
    StatusCode::NOT_FOUND.into_response().into()
}

/// The login kcc signs in to `router` with, when `user` may read its profile.
// cancel-safe: reads only.
pub(crate) async fn profile_login(
    state: &WebState,
    user: &CurrentUser,
    router: &str,
) -> Option<String> {
    let fleet = state.fleet()?;
    context::lookup(fleet, user.role(), router)
        .await
        .ok()
        .flatten()
        .map(|entry| entry.profile.login)
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use super::{merged, value, values, with_query};

    #[test]
    fn action_queries_round_trip_through_the_resubmitted_url() {
        let url = with_query(
            "/ui/r/home/system/users",
            &[("name", "a b"), ("tag", "cli")],
        );
        assert_eq!(url, "/ui/r/home/system/users?name=a+b&tag=cli", "encoded");
        let query = url.split_once('?').map(|(_, query)| query);
        let pairs = merged(query, vec![("tag".to_owned(), " http ".to_owned())]);
        assert_eq!(value(&pairs, "name"), Some("a b"), "decoded");
        assert_eq!(
            values(&pairs, "tag"),
            ["cli", "http"],
            "query then form, trimmed"
        );
        assert_eq!(value(&pairs, "missing"), None, "absent");
    }
}
