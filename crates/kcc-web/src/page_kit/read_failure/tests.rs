//! Every arm of the read-failure mapping: the message key, the HTTP status it names and
//! the value-free detail.

#![cfg(test)]
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#![expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]

use core::error::Error;

use fluent_bundle::FluentArgs;
use kcc_domain::DomainError;
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_rci::{AuthError, RciError, RciResponse, TransportCause, not_json};
use serde_json::json;

use super::{ReadProblem, rci_problem, read_problem};
use crate::page_kit::family::Family;

/// The problem `error` reads as on a domain page.
fn changes(error: RciError) -> ReadProblem {
    read_problem(Family::Changes, &DomainError::Rci(error))
}

#[test]
fn no_answer_is_unreachable_with_its_cause() {
    let cause = TransportCause::ClosedBeforeAnswer;
    let problem = changes(RciError::Transport(cause));
    assert_eq!(problem.key(), keys::WEB_KIT_UNREACHABLE, "class");
    assert_eq!(problem.detail(), Some(cause.to_string().as_str()), "cause");
    let commands = rci_problem(Family::Commands, &RciError::Transport(cause));
    assert_eq!(
        commands.key(),
        keys::WEB_EXPLORER_UNREACHABLE,
        "family words"
    );
}

#[test]
fn a_timeout_and_a_refused_sign_in_keep_their_messages() {
    let timeout = changes(RciError::Timeout);
    assert_eq!(timeout.key(), keys::ERRORS_TIMEOUT, "timeout");
    assert_eq!(timeout.detail(), None, "no detail");
    let auth = changes(RciError::Auth(AuthError::Rejected));
    assert_eq!(auth.key(), keys::ERRORS_ROUTER_AUTH, "sign-in");
    assert_eq!(auth.detail(), None, "no detail");
}

#[test]
fn an_http_error_names_its_status() {
    let problem = changes(RciError::Http { status: 502 });
    assert_eq!(problem.key(), keys::WEB_KIT_HTTP_ERROR, "class");
    let mut args = FluentArgs::new();
    args.set("status", "502");
    assert_eq!(
        problem.text(Locale::En),
        tr(Locale::En, keys::WEB_KIT_HTTP_ERROR, Some(&args)),
        "the status is a message argument"
    );
    assert_eq!(problem.detail(), None, "no detail");
}

#[test]
fn a_router_error_shows_its_ident_and_code_but_not_its_message() -> Result<(), Box<dyn Error>> {
    let answer = json!({"system": {"status": [{
        "status": "error", "code": "7405600", "ident": "Core::Configurator",
        "message": "secret-looking router text"}]}});
    let Err(error) = RciResponse::from_value(answer) else {
        return Err("an error status must be an error".into());
    };
    let problem = changes(error);
    assert_eq!(problem.key(), keys::WEB_KIT_ROUTER_ERROR, "class");
    assert_eq!(
        problem.detail(),
        Some("Core::Configurator 7405600"),
        "detail"
    );
    Ok(())
}

#[test]
fn a_missing_resource_or_method_is_not_found() {
    for error in [RciError::NotFound, RciError::MethodNotAllowed] {
        assert_eq!(changes(error).key(), keys::WEB_KIT_NOT_FOUND, "class");
    }
    let commands = rci_problem(Family::Commands, &RciError::NotFound);
    assert_eq!(commands.key(), keys::WEB_EXPLORER_NOT_FOUND, "family words");
}

#[test]
fn a_large_answer_and_a_policy_refusal_have_their_own_messages() {
    assert_eq!(
        changes(RciError::BodyTooLarge).key(),
        keys::WEB_KIT_TOO_LARGE,
        "too large"
    );
    let policy = changes(RciError::Policy);
    assert_eq!(policy.key(), keys::WEB_KIT_POLICY, "policy");
    assert_eq!(policy.detail(), None, "no detail");
}

#[test]
fn an_undecodable_answer_is_unreadable_with_its_place() {
    let detail = not_json("show ip route", b"<html>");
    let expected = detail.to_string();
    let engine = changes(RciError::Decode(detail.clone()));
    assert_eq!(engine.key(), keys::WEB_KIT_UNREADABLE, "engine decode");
    assert_eq!(engine.detail(), Some(expected.as_str()), "engine detail");
    let domain = read_problem(Family::Changes, &DomainError::UnreadableAnswer(detail));
    assert_eq!(domain.key(), keys::WEB_KIT_UNREADABLE, "domain decode");
    assert_eq!(domain.detail(), Some(expected.as_str()), "domain detail");
    let invalid = read_problem(Family::Changes, &DomainError::InvalidResponse);
    assert_eq!(invalid.key(), keys::WEB_KIT_UNREADABLE, "invalid response");
    assert_eq!(invalid.detail(), None, "no detail");
}

#[test]
fn anything_else_failed_in_the_family_words() {
    assert_eq!(
        changes(RciError::Cancelled).key(),
        keys::WEB_KIT_FAILED,
        "cancelled"
    );
    assert_eq!(
        changes(RciError::Validation).key(),
        keys::WEB_KIT_FAILED,
        "validation"
    );
    let denied = read_problem(Family::Commands, &DomainError::PermissionDenied);
    assert_eq!(
        denied.key(),
        keys::WEB_EXPLORER_FAILED,
        "other domain errors"
    );
}
