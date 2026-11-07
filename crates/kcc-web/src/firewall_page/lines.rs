//! The firewall's CLI lines, each paired with the catalog-validated request it stands for.
//!
//! The firewall domain validates rule fields, rule properties and bindings against the
//! router's catalog, but its own rendering drops the protocol and the `port eq` and
//! `disable` keywords, and the catalog cannot check the `rule ... disable|order` forms (its
//! `order` argument has no type). The page therefore writes the documented CLI form (CLI
//! manual 3.3.3 and 3.3.4) itself: every variable word comes from a catalog-validated field,
//! a name the page checked as one CLI word, or a position read fresh from the router; every
//! literal word comes from the documented synopsis.

use kcc_app::{
    permissions::Permission,
    workflow::{CliChangeRequest, CliCommand as ValidatedCli},
};
use kcc_catalog::{HttpMethod, ValidatedRequest};
use kcc_domain::{
    ChangeOp, DomainError, RouterCtx,
    firewall::{
        change::{self, RuleProperty},
        model::Direction,
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

/// The last request of a domain plan: the leaf the line stands for.
///
/// # Errors
///
/// Returns the domain's invalid-response error for an empty plan.
fn leaf(op: ChangeOp) -> Result<ValidatedRequest, DomainError> {
    op.requests
        .into_iter()
        .last()
        .ok_or(DomainError::InvalidResponse)
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

/// `no ` before `line` when `negated`.
fn negated(line: String, negate: bool) -> String {
    if negate { format!("no {line}") } else { line }
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
    let checked = leaf(change::plan_add_rule(domain, list, &rule.domain())?)?;
    let line = format!("access-list {list} {}", rule.words().join(" "));
    Ok(request(line, checked))
}

/// Removes the rule stored as `words` from the list `list`.
///
/// # Errors
///
/// Returns the catalog's findings on the rule's fields.
pub(crate) fn remove_rule(
    domain: &RouterCtx,
    list: &str,
    (rule, words): (&Parsed, &[String]),
) -> Result<CliChangeRequest, DomainError> {
    let checked = leaf(change::plan_remove_rule(domain, list, &rule.domain())?)?;
    let line = format!("no access-list {list} {}", words.join(" "));
    Ok(request(line, checked))
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
    (index, enabled): (usize, bool),
) -> Result<CliChangeRequest, DomainError> {
    drop(validated(domain, "access-list", &json!({"name": list}))?);
    let body = if enabled {
        json!({"index": index, "no": true})
    } else {
        json!({"index": index})
    };
    let checked = validated(domain, "access-list rule", &body)?;
    let line = negated(format!("access-list {list} rule {index} disable"), enabled);
    Ok(request(line, checked))
}

/// Sets the description of rule `index` of the list `list`, or removes it for `None`.
///
/// # Errors
///
/// Returns the catalog's findings on the list, the position and the description.
pub(crate) fn description(
    domain: &RouterCtx,
    list: &str,
    (index, text): (usize, Option<&str>),
) -> Result<CliChangeRequest, DomainError> {
    property(
        domain,
        list,
        index,
        ("description", text, RuleProperty::Description),
    )
}

/// Sets the schedule of rule `index` of the list `list`, or removes it for `None`.
///
/// # Errors
///
/// Returns the catalog's findings on the list, the position and the schedule.
pub(crate) fn schedule(
    domain: &RouterCtx,
    list: &str,
    (index, name): (usize, Option<&str>),
) -> Result<CliChangeRequest, DomainError> {
    property(
        domain,
        list,
        index,
        ("schedule", name, RuleProperty::Schedule),
    )
}

/// Sets the property `keyword` of rule `index` to `value` through the domain's plan, or
/// removes it for `None`.
///
/// # Errors
///
/// Returns the catalog's findings.
fn property<'value>(
    domain: &RouterCtx,
    list: &str,
    index: usize,
    (keyword, value, make): (
        &str,
        Option<&'value str>,
        fn(&'value str) -> RuleProperty<'value>,
    ),
) -> Result<CliChangeRequest, DomainError> {
    let position = u32::try_from(index).map_err(|_error| DomainError::InvalidResponse)?;
    let Some(given) = value else {
        drop(validated(domain, "access-list", &json!({"name": list}))?);
        let checked = validated(
            domain,
            "access-list rule",
            &json!({"index": index, "no": true}),
        )?;
        let line = format!("no access-list {list} rule {index} {keyword}");
        return Ok(request(line, checked));
    };
    let checked = leaf(change::plan_rule_property(
        domain,
        list,
        position,
        make(given),
    )?)?;
    let word = if keyword == "description" {
        format!("\"{given}\"")
    } else {
        given.to_owned()
    };
    let line = format!("access-list {list} rule {index} {keyword} {word}");
    Ok(request(line, checked))
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
    let checked = leaf(change::plan_bind(
        domain, interface, list, direction, enabled,
    )?)?;
    let line = negated(
        format!(
            "interface {interface} ip access-group {list} {}",
            direction.name()
        ),
        !enabled,
    );
    Ok(request(line, checked))
}
