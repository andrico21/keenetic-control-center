//! Catalog validation as the explorer and the consoles report it: bodies wrapped for the
//! root RCI endpoint, and every problem with a request as a localized sentence.

use askama::Template;
use axum::response::Response;
use fluent_bundle::FluentArgs;
use kcc_catalog::{HttpMethod, Risk, ValidationIssue};
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};
use serde_json::{Map, Value};

use super::{context::fragment_shell, detail::encode};
use crate::{
    errors,
    page::{Localize, Shell},
};

/// Most items one RCI console batch may hold.
pub(crate) const MAX_BATCH: usize = 50;

/// What is wrong with a request before it may be sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Problem {
    /// The catalog rejected the request.
    Issue(ValidationIssue),
    /// One item of a batch was rejected; `index` counts from 1.
    Item {
        /// Item position, from 1.
        index: usize,
        /// The catalog's finding.
        issue: ValidationIssue,
    },
    /// The body is not JSON.
    Json {
        /// Line of the syntax error.
        line: usize,
        /// Column of the syntax error.
        column: usize,
    },
    /// The root endpoint takes only POST with an object or a list of objects.
    Root,
    /// A batch is empty or holds more than [`MAX_BATCH`] items.
    BatchSize,
    /// The path cannot be a URL path, so it can only be sent at the root.
    Segment {
        /// The rejected path.
        path: String,
    },
    /// The input is empty or longer than allowed.
    Length,
}

/// The root RCI object that runs `path` with `body`:
/// `ip hotspot host` and `{..}` become `{"ip":{"hotspot":{"host":{..}}}}`.
pub(crate) fn root_object(path: &str, body: Value) -> Value {
    path.split_whitespace().rev().fold(body, |inner, word| {
        let mut object = Map::new();
        drop(object.insert(word.to_owned(), inner));
        Value::Object(object)
    })
}

/// The HTTP method name.
pub(crate) const fn method_name(method: HttpMethod) -> &'static str {
    match method {
        HttpMethod::Get => "GET",
        HttpMethod::Post => "POST",
        HttpMethod::Delete | _ => "DELETE",
    }
}

/// A localized sentence for `problem`.
pub(crate) fn sentence(locale: Locale, problem: &Problem) -> String {
    let mut args = FluentArgs::new();
    let key = match problem {
        Problem::Issue(issue) => return issue_sentence(locale, issue),
        Problem::Item { index, issue } => {
            args.set("index", index.to_string());
            args.set("issue", issue_sentence(locale, issue));
            keys::WEB_EXPLORER_ISSUE_ITEM
        }
        Problem::Json { line, column } => {
            args.set("line", line.to_string());
            args.set("column", column.to_string());
            keys::WEB_EXPLORER_ISSUE_JSON
        }
        Problem::Root => keys::WEB_EXPLORER_ISSUE_ROOT,
        Problem::BatchSize => {
            args.set("count", MAX_BATCH.to_string());
            keys::WEB_EXPLORER_ISSUE_BATCH
        }
        Problem::Segment { path } => {
            args.set("path", path.clone());
            keys::WEB_EXPLORER_ISSUE_SEGMENT
        }
        Problem::Length => keys::WEB_EXPLORER_ISSUE_LENGTH,
    };
    tr(locale, key, Some(&args))
}

/// A localized sentence for one catalog finding.
fn issue_sentence(locale: Locale, issue: &ValidationIssue) -> String {
    let mut args = FluentArgs::new();
    let key = match issue {
        ValidationIssue::UnknownPath { path } => {
            args.set("path", path.clone());
            keys::WEB_EXPLORER_ISSUE_UNKNOWN_PATH
        }
        ValidationIssue::MethodNotAllowed { method } => {
            args.set("method", method_name(*method));
            keys::WEB_EXPLORER_ISSUE_METHOD
        }
        ValidationIssue::ExpectedObject { field } => {
            args.set("field", display_field(field));
            keys::WEB_EXPLORER_ISSUE_OBJECT
        }
        ValidationIssue::UnknownField {
            field,
            suggestion: Some(suggestion),
        } => {
            args.set("field", display_field(field));
            args.set("suggestion", suggestion.clone());
            keys::WEB_EXPLORER_ISSUE_SUGGESTION
        }
        ValidationIssue::UnknownField {
            field,
            suggestion: None,
        } => {
            args.set("field", display_field(field));
            keys::WEB_EXPLORER_ISSUE_UNKNOWN_FIELD
        }
        ValidationIssue::InvalidValue { field } => {
            args.set("field", display_field(field));
            keys::WEB_EXPLORER_ISSUE_VALUE
        }
        ValidationIssue::NoPrefixUnsupported => keys::WEB_EXPLORER_ISSUE_NO,
        ValidationIssue::InvalidCliSyntax => keys::WEB_EXPLORER_ISSUE_CLI_SYNTAX,
        ValidationIssue::UnsupportedCliSyntax { path } => {
            args.set("path", path.clone());
            keys::WEB_EXPLORER_ISSUE_CLI_FORM
        }
        ValidationIssue::RawAuthorizationRequired | _ => keys::WEB_EXPLORER_ISSUE_RAW,
    };
    tr(locale, key, Some(&args))
}

/// A field path as people read it; the root of a body is shown as `/`.
fn display_field(field: &str) -> String {
    if field.is_empty() {
        "/".to_owned()
    } else {
        field.to_owned()
    }
}

/// The live result of a console check: valid with its risk and the explorer link of
/// its command, or the problems that stop it.
#[derive(Template)]
#[template(path = "partials/console_check.html")]
pub(crate) struct Report {
    /// Locale carrier.
    shell: Shell,
    /// Localized summary.
    summary: String,
    /// Problems; empty when valid.
    problems: Vec<String>,
    /// Risk label of a valid request.
    risk: Option<MessageKey>,
    /// Explorer link of the command the request maps to.
    explore: Option<String>,
}

impl Localize for Report {
    fn shell(&self) -> &Shell {
        &self.shell
    }
}

impl Report {
    /// A valid request summarized by `summary`.
    pub(crate) const fn valid(summary: String, risk: Risk) -> Self {
        Self {
            shell: fragment_shell(Locale::En),
            summary,
            problems: Vec::new(),
            risk: Some(risk_key(risk)),
            explore: None,
        }
    }

    /// A request stopped by `problems`.
    pub(crate) fn invalid(locale: Locale, problems: &[Problem]) -> Self {
        Self {
            shell: fragment_shell(locale),
            summary: tr(locale, keys::WEB_EXPLORER_INVALID, None),
            problems: problems
                .iter()
                .map(|found| sentence(locale, found))
                .collect(),
            risk: None,
            explore: None,
        }
    }

    /// Links the catalog command `path` in the explorer of `router`.
    pub(crate) fn with_explore(mut self, router: &str, path: Option<&str>) -> Self {
        self.explore =
            path.map(|command| format!("/ui/r/{router}/explorer?path={}", encode(command)));
        self
    }

    /// The fragment in `locale`.
    pub(crate) fn respond(mut self, locale: Locale) -> Response {
        self.shell = fragment_shell(locale);
        errors::render(&self)
    }
}

/// The label of a catalog risk.
pub(crate) const fn risk_key(risk: Risk) -> MessageKey {
    match risk {
        Risk::Read => keys::WEB_EXPLORER_RISK_READ,
        Risk::Write => keys::WEB_EXPLORER_RISK_WRITE,
        Risk::Management => keys::WEB_EXPLORER_RISK_MANAGEMENT,
        Risk::Destructive | _ => keys::WEB_EXPLORER_RISK_DESTRUCTIVE,
    }
}

/// The issues of a failed validation, wrapped as problems.
pub(crate) fn from_issues(issues: Vec<ValidationIssue>) -> Vec<Problem> {
    issues.into_iter().map(Problem::Issue).collect()
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use kcc_catalog::ValidationIssue;
    use kcc_i18n::locale::Locale;
    use serde_json::json;

    use super::{Problem, root_object, sentence};

    #[test]
    fn bodies_nest_under_their_command_words() {
        assert_eq!(
            root_object("ip hotspot host", json!({"mac": "02:00:00:00:00:01"})),
            json!({"ip": {"hotspot": {"host": {"mac": "02:00:00:00:00:01"}}}}),
            "nested root object"
        );
    }

    #[test]
    fn findings_read_as_sentences_naming_the_field() {
        let incident = sentence(
            Locale::En,
            &Problem::Issue(ValidationIssue::ExpectedObject {
                field: "ip.route".to_owned(),
            }),
        );
        assert!(incident.contains("ip.route"), "{incident}");
        let item = sentence(
            Locale::En,
            &Problem::Item {
                index: 2,
                issue: ValidationIssue::NoPrefixUnsupported,
            },
        );
        assert!(item.contains('2'), "{item}");
    }
}
