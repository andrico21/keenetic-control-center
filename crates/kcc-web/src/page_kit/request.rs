//! What the Web pages read from a request and build back into one.
//!
//! A page reads its parameters and the page the browser shows, and builds the addresses
//! of its actions, a region rendered out of band and the answer to a name it does not
//! have.
//!
//! The parameters of an action are its query string and its form body together
//! ([`Params`]), so the confirmation dialog of a change made from another dialog can send
//! the values again from its own address. The last value of a repeated name counts.

use askama::Template;
use axum::{
    http::{HeaderMap, StatusCode, Uri},
    response::IntoResponse as _,
};
use kcc_rci::ObjectName;
use serde_json::{Map, Value};
use url::{Url, form_urlencoded};

use crate::{
    markup::Rendered,
    page_kit::{confirm::Confirmation, respond::Answer},
    table::rows::TableQuery,
};

/// The parameters of an action: its query string, then its form body; the last value of
/// a name counts.
#[derive(Debug, Default)]
pub(crate) struct Params(Vec<(String, String)>);

impl Params {
    /// The parameters of a request with `query` and `form`.
    pub(crate) fn new(query: Vec<(String, String)>, form: Vec<(String, String)>) -> Self {
        Self(query.into_iter().chain(form).collect())
    }

    /// The parameters `pairs` of one submission.
    pub(crate) const fn of(pairs: Vec<(String, String)>) -> Self {
        Self(pairs)
    }

    /// The value of `name` as sent.
    pub(crate) fn get(&self, name: &str) -> Option<&str> {
        last(&self.0, name)
    }

    /// The value of `name` as sent, empty when absent.
    pub(crate) fn text(&self, name: &str) -> &str {
        self.get(name).unwrap_or_default()
    }

    /// The object named by `name`.
    ///
    /// # Errors
    ///
    /// Answers 404 when the name is absent or is not a valid object name.
    pub(crate) fn object(&self, name: &str) -> Result<ObjectName, Answer> {
        self.get(name)
            .and_then(|value| ObjectName::try_from(value.to_owned()).ok())
            .ok_or_else(missing)
    }

    /// The confirmation the request carries.
    pub(crate) fn confirmation(&self) -> Confirmation {
        Confirmation::from_pairs(&self.0)
    }

    /// The address that sends the parameters to `path` again, as its query string,
    /// without the confirmation's own fields.
    pub(crate) fn again(&self, path: &str) -> String {
        let kept: Vec<(&str, &str)> = self
            .0
            .iter()
            .filter(|(name, _)| name != "confirm" && name != "confirm_name")
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect();
        if kept.is_empty() {
            path.to_owned()
        } else {
            with_query(path, &kept)
        }
    }
}

/// The last value of `name` in `pairs`, as sent.
pub(crate) fn last<'pairs>(pairs: &'pairs [(String, String)], name: &str) -> Option<&'pairs str> {
    pairs
        .iter()
        .rev()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.as_str())
}

/// `path` with `pairs` as its query string.
pub(crate) fn with_query(path: &str, pairs: &[(&str, &str)]) -> String {
    let mut query = form_urlencoded::Serializer::new(String::new());
    for (name, value) in pairs {
        let _: &mut form_urlencoded::Serializer<'_, String> = query.append_pair(name, value);
    }
    format!("{path}?{}", query.finish())
}

/// The address of the page the browser shows, from htmx's `HX-Current-URL`.
pub(crate) fn shown_url(headers: &HeaderMap) -> Option<&str> {
    headers.get("hx-current-url")?.to_str().ok()
}

/// The page the browser shows, so a region read back after a change keeps its view.
pub(crate) fn shown_uri(headers: &HeaderMap) -> Option<Uri> {
    shown_url(headers)?.parse().ok()
}

/// The table query of the page the browser shows, so a table sent again after a change
/// keeps its filter, sort and page.
pub(crate) fn shown_query(headers: &HeaderMap) -> TableQuery {
    let fields: Map<String, Value> = shown_url(headers)
        .and_then(|value| Url::parse(value).ok())
        .map_or_default(|url| {
            url.query_pairs()
                .map(|(name, value)| (name.into_owned(), Value::String(value.into_owned())))
                .collect()
        });
    serde_json::from_value(Value::Object(fields)).unwrap_or_default()
}

/// `region` rendered for sending out of band; a failed render is logged and leaves the
/// page as it is.
pub(crate) fn rendered<T>(region: &T) -> Option<Rendered>
where
    T: Template,
{
    Rendered::of(region)
        .inspect_err(|error| tracing::error!(%error, "page region failed to render"))
        .ok()
}

/// The 404 answer to an object, a value or a route segment the page does not have.
pub(crate) fn missing() -> Answer {
    StatusCode::NOT_FOUND.into_response().into()
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use axum::http::{HeaderMap, HeaderValue};

    use super::{Params, shown_query, shown_uri, with_query};

    fn pair(name: &str, value: &str) -> (String, String) {
        (name.to_owned(), value.to_owned())
    }

    fn showing(url: &[u8]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if let Ok(value) = HeaderValue::from_bytes(url) {
            drop(headers.insert("hx-current-url", value));
        }
        headers
    }

    #[test]
    fn the_form_value_after_the_query_value_counts_as_sent() {
        let params = Params::new(
            vec![pair("name", "query"), pair("tag", "a")],
            vec![pair("name", " form "), pair("name", " last ")],
        );
        assert_eq!(params.get("name"), Some(" last "), "last value, untrimmed");
        assert_eq!(params.get("tag"), Some("a"), "query only");
        assert_eq!(params.get("absent"), None, "absent");
        assert_eq!(params.text("absent"), "", "absent text is empty");
    }

    #[test]
    fn query_pairs_are_encoded_after_the_path() {
        assert_eq!(
            with_query("/ui/r/home/dns", &[("name", "a b&c"), ("tag", "\u{e9}")]),
            "/ui/r/home/dns?name=a+b%26c&tag=%C3%A9",
        );
    }

    #[test]
    fn the_shown_query_is_the_table_part_of_the_current_url_last_value_wins() {
        let headers = showing(b"http://kcc.test/ui/r/home/dns?q=a&q=b%20c&page=2&tab=x");
        assert_eq!(
            shown_query(&headers).parts(),
            [Some("b c"), None, None, Some("2")]
        );
        assert_eq!(
            shown_uri(&headers).map(|uri| uri.path().to_owned()),
            Some("/ui/r/home/dns".to_owned())
        );
    }

    #[test]
    fn a_missing_or_unreadable_current_url_shows_the_default_view() {
        for headers in [HeaderMap::new(), showing(b"not a url"), showing(b"\xff")] {
            assert_eq!(shown_query(&headers).parts(), [None; 4]);
        }
        assert!(shown_uri(&HeaderMap::new()).is_none(), "no header");
    }
}
