//! Localized sentences for catalog validation issues.

use fluent_bundle::FluentArgs;
use kcc_catalog::{HttpMethod, ValidationIssue};
use kcc_i18n::{bundle::tr, keys, locale::Locale};

/// One validation issue as a sentence, worded like the Web UI's explorer.
pub(crate) fn issue_sentence(locale: Locale, issue: &ValidationIssue) -> String {
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
            args.set("field", shown(field));
            keys::WEB_EXPLORER_ISSUE_OBJECT
        }
        ValidationIssue::UnknownField {
            field,
            suggestion: Some(suggestion),
        } => {
            args.set("field", shown(field));
            args.set("suggestion", suggestion.clone());
            keys::WEB_EXPLORER_ISSUE_SUGGESTION
        }
        ValidationIssue::UnknownField {
            field,
            suggestion: None,
        } => {
            args.set("field", shown(field));
            keys::WEB_EXPLORER_ISSUE_UNKNOWN_FIELD
        }
        ValidationIssue::InvalidValue { field } => {
            args.set("field", shown(field));
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

/// The HTTP method name.
pub(crate) const fn method_name(method: HttpMethod) -> &'static str {
    match method {
        HttpMethod::Get => "GET",
        HttpMethod::Post => "POST",
        HttpMethod::Delete | _ => "DELETE",
    }
}

/// A field path as people read it; the root of a body is `/`.
fn shown(field: &str) -> String {
    if field.is_empty() {
        "/".to_owned()
    } else {
        field.to_owned()
    }
}
