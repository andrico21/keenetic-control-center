//! Planning of access-list rule additions and removals.

use alloc::{format, vec};

use kcc_catalog::ValidationIssue;
use serde_json::{Map, Value, json};

use super::{
    super::model::{Protocol, Rule},
    Plan, PortSide, contextual, insert, request,
    verify::Verification,
};
use crate::{DomainError, Result, RouterCtx};

/// Plans adding or removing the rule `rule` in the access list `name`.
///
/// # Errors
///
/// Returns [`DomainError::Validation`] for a port on a protocol other than TCP or UDP, a
/// port range whose end comes first, or a request the catalog refuses, and
/// [`DomainError::InvalidCliToken`] for an invalid list name.
pub(super) fn plan_rule(router: &RouterCtx, name: &str, rule: &Rule, remove: bool) -> Result<Plan> {
    if !matches!(rule.protocol, Protocol::Tcp | Protocol::Udp) {
        // The manuals document port matches only for `tcp` and `udp` rules.
        let ported = [
            ("source-port", rule.source_port.or(rule.source_end_port)),
            (
                "destination-port",
                rule.destination_port.or(rule.destination_end_port),
            ),
        ];
        let issues: Vec<ValidationIssue> = ported
            .into_iter()
            .filter(|(_field, port)| port.is_some())
            .map(|(field, _port)| ValidationIssue::InvalidValue {
                field: field.to_owned(),
            })
            .collect();
        if !issues.is_empty() {
            return Err(DomainError::Validation { issues });
        }
    }
    let mut body = json!({"source":rule.source,"source-mask":rule.source_mask,"destination":rule.destination,"destination-mask":rule.destination_mask});
    let fields = body.as_object_mut().ok_or(DomainError::InvalidResponse)?;
    insert_port(
        fields,
        PortSide::Source,
        rule.source_port,
        rule.source_end_port,
    )?;
    insert_port(
        fields,
        PortSide::Destination,
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
    let plan = Plan {
        operation,
        verification,
    };
    // The rule line must render the planned request.
    drop(request(&plan)?);
    Ok(plan)
}

/// Inserts the port fields of one side of a rule.
///
/// # Errors
///
/// Returns [`DomainError::Validation`] naming the end port when a range has no start or
/// its end comes first.
fn insert_port(
    fields: &mut Map<String, Value>,
    side: PortSide,
    start: Option<u16>,
    end: Option<u16>,
) -> Result<()> {
    let (port, end_port, operator) = side.fields();
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
        (None | Some(_), Some(_)) => Err(DomainError::Validation {
            issues: vec![ValidationIssue::InvalidValue {
                field: end_port.to_owned(),
            }],
        }),
    }
}
