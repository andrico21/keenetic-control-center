//! Catalog-validated firewall planning and protected execution.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_inline_in_public_items,
    reason = "protected mutations are not inline candidates"
)]
#![cfg_attr(
    not(test),
    expect(
        clippy::missing_docs_in_private_items,
        reason = "private validation and body assembly helpers are narrowly named"
    )
)]

mod render;
mod verify;

use alloc::{format, vec};

use kcc_app::{
    permissions::Permission,
    workflow::{ChangeSet, CliChangeRequest, CliChangeResult, WorkflowError},
};
use kcc_catalog::{HttpMethod, Risk, ValidatedRequest};
use serde_json::{Map, Value, json};

use self::verify::{OwnedRuleProperty, Verification};
use super::model::{ConfiguredRule, Direction, Rule};
use crate::{ChangeOp, DomainError, Result, RouterCtx};

/// A catalog-validated firewall operation with its full-identity read-back contract.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub struct Plan {
    operation: ChangeOp,
    verification: Verification,
}

impl Plan {
    /// Returns the validated generic operation metadata.
    #[inline]
    #[must_use]
    pub const fn operation(&self) -> &ChangeOp {
        &self.operation
    }
}

/// Converts a validated firewall change into protected CLI workflow input.
pub fn request(change: &Plan) -> Result<CliChangeRequest> {
    render::request(&change.operation, &change.verification)
}

/// Plans adding one access-list rule.
pub fn plan_add_rule(router: &RouterCtx, name: &str, rule: &Rule) -> Result<Plan> {
    plan_rule(router, name, rule, false)
}

/// Plans removing exactly one access-list rule.
pub fn plan_remove_rule(router: &RouterCtx, name: &str, rule: &Rule) -> Result<Plan> {
    plan_rule(router, name, rule, true)
}

/// Plans one rule order, description, disable, or schedule property.
pub fn plan_rule_property(
    router: &RouterCtx,
    name: &str,
    rule: &ConfiguredRule,
    property: RuleProperty<'_>,
) -> Result<Plan> {
    let index = u32::try_from(rule.index).map_err(|_error| DomainError::InvalidResponse)?;
    let body = match property {
        RuleProperty::Description(Some(value)) => json!({"index":index,"description":value}),
        RuleProperty::Description(None) | RuleProperty::Schedule(None) => {
            json!({"index":index,"no":true})
        }
        RuleProperty::Disable(enabled) => {
            if enabled {
                json!({"index":index})
            } else {
                json!({"index":index,"no":true})
            }
        }
        RuleProperty::Schedule(Some(value)) => json!({"index":index,"schedule":value}),
        RuleProperty::Order(position) => json!({"index":index,"order":position}),
    };
    Ok(Plan {
        operation: contextual(router, name, "access-list rule", &body)?,
        verification: Verification::Property {
            list: name.to_owned(),
            before: rule.clone(),
            property: property.owned(),
        },
    })
}

/// Rule metadata property.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RuleProperty<'value> {
    /// Optional human-readable rule description.
    Description(Option<&'value str>),
    /// Whether the indexed rule is disabled.
    Disable(bool),
    /// Optional named schedule.
    Schedule(Option<&'value str>),
    /// New rule position, counted from zero.
    Order(usize),
}

impl RuleProperty<'_> {
    fn owned(self) -> OwnedRuleProperty {
        match self {
            Self::Description(value) => OwnedRuleProperty::Description(value.map(str::to_owned)),
            Self::Disable(value) => OwnedRuleProperty::Disable(value),
            Self::Schedule(value) => OwnedRuleProperty::Schedule(value.map(str::to_owned)),
            Self::Order(value) => OwnedRuleProperty::Order(value),
        }
    }
}

/// Plans binding an IPv4 access list to an interface.
pub fn plan_bind(
    router: &RouterCtx,
    interface: &str,
    acl: &str,
    direction: Direction,
    enabled: bool,
) -> Result<Plan> {
    let context = validate(router, "interface", &json!({"name":interface}))?;
    let mut body = json!({"acl":acl,"direction":direction.name()});
    if !enabled {
        insert(
            body.as_object_mut().ok_or(DomainError::InvalidResponse)?,
            "no",
            json!(true),
        );
    }
    let leaf = validate(router, "interface ip access-group", &body)?;
    Ok(Plan {
        operation: operation(vec![context, leaf]),
        verification: Verification::Binding {
            interface: interface.to_owned(),
            list: acl.to_owned(),
            direction,
            present: enabled,
        },
    })
}

/// Applies a firewall plan and verifies the full identity in a fresh running config.
pub async fn apply(
    changes: &mut ChangeSet,
    router: &RouterCtx,
    change: &Plan,
) -> Result<CliChangeResult> {
    change.verification.preflight(router).await?;
    let result = changes.apply_cli(request(change)?).await.map_err(|error| {
        if matches!(error, WorkflowError::VerificationFailed { field: _ }) {
            DomainError::FirewallVerificationFailed
        } else {
            DomainError::Workflow(error)
        }
    })?;
    change.verification.verify(router).await?;
    Ok(result)
}

fn plan_rule(router: &RouterCtx, name: &str, rule: &Rule, remove: bool) -> Result<Plan> {
    let mut body = json!({"source":rule.source,"source-mask":rule.source_mask,"destination":rule.destination,"destination-mask":rule.destination_mask});
    let fields = body.as_object_mut().ok_or(DomainError::InvalidResponse)?;
    insert_port(fields, "source", rule.source_port, rule.source_end_port)?;
    insert_port(
        fields,
        "destination",
        rule.destination_port,
        rule.destination_end_port,
    )?;
    if remove {
        insert(fields, "no", json!(true));
    }
    let operation = contextual(
        router,
        name,
        &format!("access-list {}", rule.action.name()),
        &body,
    )?;
    let verification = if remove {
        Verification::Remove {
            list: name.to_owned(),
            rule: rule.clone(),
        }
    } else {
        Verification::Add {
            list: name.to_owned(),
            rule: rule.clone(),
        }
    };
    Ok(Plan {
        operation,
        verification,
    })
}

fn insert_port(
    fields: &mut Map<String, Value>,
    side: &str,
    start: Option<u16>,
    end: Option<u16>,
) -> Result<()> {
    let (port, end_port, operator) = match side {
        "source" => ("source-port", "source-end-port", "src-port-operator"),
        "destination" => (
            "destination-port",
            "destination-end-port",
            "dst-port-operator",
        ),
        _ => return Err(DomainError::InvalidResponse),
    };
    match (start, end) {
        (None, None) => Ok(()),
        (Some(value), None) => {
            insert(fields, operator, json!("eq"));
            insert(fields, port, json!(value));
            Ok(())
        }
        (Some(first), Some(last)) if first <= last => {
            insert(fields, port, json!(first));
            insert(fields, end_port, json!(last));
            Ok(())
        }
        (None | Some(_), Some(_)) => Err(DomainError::InvalidResponse),
    }
}

fn contextual(router: &RouterCtx, name: &str, path: &str, body: &Value) -> Result<ChangeOp> {
    Ok(operation(vec![
        validate(router, "access-list", &json!({"name":name}))?,
        validate(router, path, body)?,
    ]))
}

fn validate(router: &RouterCtx, path: &str, body: &Value) -> Result<ValidatedRequest> {
    router
        .catalog
        .validate(path, HttpMethod::Post, body)
        .map_err(|issues| DomainError::Validation { issues })
}

const fn operation(requests: Vec<ValidatedRequest>) -> ChangeOp {
    ChangeOp::new(requests, Vec::new(), Risk::Write, Permission::Write, false)
}

fn insert(fields: &mut Map<String, Value>, name: &str, value: Value) {
    drop(fields.insert(name.to_owned(), value));
}
