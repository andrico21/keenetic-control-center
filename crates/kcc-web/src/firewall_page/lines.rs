//! Firewall CLI requests, delegating validated rule rendering to the domain.

use kcc_app::{
    permissions::Permission,
    workflow::{CliChangeRequest, CliCommand as ValidatedCli},
};
use kcc_catalog::{HttpMethod, ValidatedRequest};
use kcc_domain::{
    DomainError, RouterCtx,
    firewall::{
        change::{self, RuleProperty},
        model::{ConfiguredRule, Direction},
    },
};
use serde_json::{Value, json};

use super::rule::Parsed;

/// The request of one firewall `line`, standing for `leaf`.
fn request(line: String, leaf: ValidatedRequest) -> CliChangeRequest {
    CliChangeRequest::new(
        vec![ValidatedCli::new(line, leaf)],
        Vec::new(),
        Permission::Write,
        json!({"domain": "firewall"}),
    )
}

/// `body` of `path` validated by the router's catalog.
///
/// # Errors
///
/// Returns the catalog's findings.
fn validated(
    domain: &RouterCtx,
    path: &str,
    body: &Value,
) -> Result<ValidatedRequest, DomainError> {
    domain
        .catalog
        .validate(path, HttpMethod::Post, body)
        .map_err(|issues| DomainError::Validation { issues })
}

/// Adds `rule` to the list `list`, in the documented form.
///
/// # Errors
///
/// Returns the catalog's findings on the rule's fields.
pub(crate) fn add_rule(
    domain: &RouterCtx,
    list: &str,
    rule: &Parsed,
) -> Result<CliChangeRequest, DomainError> {
    change::request(&change::plan_add_rule(domain, list, &rule.domain())?)
}

/// Removes the rule stored as `words` from the list `list`.
///
/// # Errors
///
/// Returns the catalog's findings on the rule's fields.
pub(crate) fn remove_rule(
    domain: &RouterCtx,
    list: &str,
    (rule, _words): (&Parsed, &[String]),
) -> Result<CliChangeRequest, DomainError> {
    change::request(&change::plan_remove_rule(domain, list, &rule.domain())?)
}

/// Moves rule `index` of the list `list` to position `to`.
///
/// # Errors
///
/// Returns the catalog's findings on the list and the position.
pub(crate) fn order(
    domain: &RouterCtx,
    list: &str,
    (index, to): (usize, usize),
) -> Result<CliChangeRequest, DomainError> {
    drop(validated(domain, "access-list", &json!({"name": list}))?);
    let checked = validated(domain, "access-list rule", &json!({"index": index}))?;
    let line = format!("access-list {list} rule {index} order {to}");
    Ok(request(line, checked))
}

/// Disables rule `index` of the list `list`, or enables it again.
///
/// # Errors
///
/// Returns the catalog's findings on the list and the position.
pub(crate) fn state(
    domain: &RouterCtx,
    list: &str,
    (rule, enabled): (&ConfiguredRule, bool),
) -> Result<CliChangeRequest, DomainError> {
    change::request(&change::plan_rule_property(
        domain,
        list,
        rule,
        RuleProperty::Disable(!enabled),
    )?)
}

/// Sets the description of rule `index` of the list `list`, or removes it for `None`.
///
/// # Errors
///
/// Returns the catalog's findings on the list, the position and the description.
pub(crate) fn description(
    domain: &RouterCtx,
    list: &str,
    (rule, text): (&ConfiguredRule, Option<&str>),
) -> Result<CliChangeRequest, DomainError> {
    change::request(&change::plan_rule_property(
        domain,
        list,
        rule,
        RuleProperty::Description(text),
    )?)
}

/// Sets the schedule of rule `index` of the list `list`, or removes it for `None`.
///
/// # Errors
///
/// Returns the catalog's findings on the list, the position and the schedule.
pub(crate) fn schedule(
    domain: &RouterCtx,
    list: &str,
    (rule, name): (&ConfiguredRule, Option<&str>),
) -> Result<CliChangeRequest, DomainError> {
    change::request(&change::plan_rule_property(
        domain,
        list,
        rule,
        RuleProperty::Schedule(name),
    )?)
}

/// Applies the list `list` to `interface` in `direction`, or stops applying it.
///
/// # Errors
///
/// Returns the catalog's findings on the interface, the list and the direction.
pub(crate) fn bind(
    domain: &RouterCtx,
    (interface, list): (&str, &str),
    direction: Direction,
    enabled: bool,
) -> Result<CliChangeRequest, DomainError> {
    change::request(&change::plan_bind(
        domain, interface, list, direction, enabled,
    )?)
}
