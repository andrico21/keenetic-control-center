//! Catalog-validated firewall planning and protected execution.

mod render;
mod rule;
mod verify;

use alloc::vec;
use core::slice;

use kcc_app::{
    permissions::Permission,
    workflow::{ChangeSet, CliChangeRequest, CliChangeResult, WorkflowError},
};
use kcc_catalog::{Risk, ValidatedRequest};
use serde_json::{Map, Value, json};

use self::verify::{OwnedRuleProperty, Verification};
use super::{
    model::{ConfiguredRule, Direction, Rule},
    rule_list::ListedRule,
};
use crate::{ChangeOp, DomainError, Result, RouterCtx, cli_token, planning::validate};

/// The side of a firewall rule a port belongs to.
#[derive(Clone, Copy)]
enum PortSide {
    /// The source port.
    Source,
    /// The destination port.
    Destination,
}

impl PortSide {
    /// The request fields of this side: the port, the range end and the port operator.
    const fn fields(self) -> (&'static str, &'static str, &'static str) {
        match self {
            Self::Source => ("source-port", "source-end-port", "src-port-operator"),
            Self::Destination => (
                "destination-port",
                "destination-end-port",
                "dst-port-operator",
            ),
        }
    }
}

/// A catalog-validated firewall operation with its full-identity read-back contract.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub struct Plan {
    /// The validated requests.
    operation: ChangeOp,
    /// How the change is read back.
    verification: Verification,
}

impl Plan {
    /// Resolves runtime management risk once before the surface authorizes execution.
    /// Unclassified plans remain management risk rather than bypassing recovery.
    // NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned
    // router session. Apart from that, only configuration and topology reads precede returning the
    // plan.
    #[inline]
    pub async fn classify(mut self, router: &RouterCtx) -> Self {
        self.operation.risk = match &self.verification {
            Verification::Binding {
                interface,
                list: _,
                direction: _,
                present: _,
            } => super::management::interfaces_risk(router, slice::from_ref(interface)).await,
            Verification::Add { list, rule: _ }
            | Verification::Remove { list, rule: _ }
            | Verification::Property {
                list,
                before: _,
                property: _,
            } => super::management::list_risk(router, list).await,
        };
        self
    }

    /// Returns the validated generic operation metadata.
    #[inline]
    #[must_use]
    pub const fn operation(&self) -> &ChangeOp {
        &self.operation
    }
}

/// Converts a validated firewall change into protected CLI workflow input.
///
/// # Errors
///
/// Returns [`DomainError::InvalidResponse`] when the plan is not a context request followed by a
/// leaf request, lacks a field, or when a command cannot be given a read-back of its own (a
/// secret-bearing command, or a line that is not exactly one configuration row);
/// [`DomainError::InvalidCliToken`] when a description cannot be quoted; and
/// [`DomainError::Workflow`] when the rendered line does not match its request.
#[inline]
pub fn request(change: &Plan) -> Result<CliChangeRequest> {
    render::request(&change.operation, &change.verification)
}

/// Plans adding one access-list rule.
///
/// # Errors
///
/// Returns an error when the catalog refuses a planned request
/// ([`DomainError::Validation`]).
#[inline]
pub fn plan_add_rule(router: &RouterCtx, name: &str, rule: &Rule) -> Result<Plan> {
    rule::plan_rule(router, name, rule, false)
}

/// Plans removing exactly one access-list rule.
///
/// # Errors
///
/// Returns an error when the catalog refuses a planned request
/// ([`DomainError::Validation`]).
#[inline]
pub fn plan_remove_rule(router: &RouterCtx, name: &str, rule: &Rule) -> Result<Plan> {
    rule::plan_rule(router, name, rule, true)
}

/// Plans one rule order, description, disable, or schedule property.
///
/// # Errors
///
/// Returns an error when the catalog refuses a planned request
/// ([`DomainError::Validation`]).
#[inline]
pub fn plan_rule_property(
    router: &RouterCtx,
    name: &str,
    rule: &ConfiguredRule,
    property: RuleProperty<'_>,
) -> Result<Plan> {
    plan_property(
        router,
        name,
        ListedRule::new(rule.index, Vec::new(), Some(rule.clone())),
        property,
    )
}

/// Plans moving `rule` of the list `name` to `position`, counted from zero, as
/// `access-list <name> rule <index> order <position>`; a rule in any stored form can move.
///
/// # Errors
///
/// Returns an error when the catalog refuses a planned request
/// ([`DomainError::Validation`]).
#[inline]
pub fn plan_order_rule(
    router: &RouterCtx,
    name: &str,
    rule: &ListedRule,
    position: usize,
) -> Result<Plan> {
    plan_property(router, name, rule.clone(), RuleProperty::Order(position))
}

/// Plans one property change of the rule at `index` in the access list `name`.
///
/// # Errors
///
/// Returns [`DomainError::Validation`] when the catalog refuses the request and
/// [`DomainError::InvalidCliToken`] for an invalid list name.
fn plan_property(
    router: &RouterCtx,
    name: &str,
    before: ListedRule,
    property: RuleProperty<'_>,
) -> Result<Plan> {
    let index = u32::try_from(before.index()).map_err(|_error| DomainError::InvalidResponse)?;
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
        RuleProperty::Order(position) => json!({"index":index,"new-index":position}),
    };
    Ok(Plan {
        operation: contextual(router, name, "access-list rule", &body)?,
        verification: Verification::Property {
            list: name.to_owned(),
            before,
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
    /// The owned form of this property, kept by the verification.
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
///
/// # Errors
///
/// Returns an error when an argument cannot be one safe router CLI word
/// ([`DomainError::InvalidCliToken`]), when the catalog refuses a planned request
/// ([`DomainError::Validation`]), or when a reply or a plan does not have the expected
/// shape ([`DomainError::InvalidResponse`]).
#[inline]
pub fn plan_bind(
    router: &RouterCtx,
    interface: &str,
    acl: &str,
    direction: Direction,
    enabled: bool,
) -> Result<Plan> {
    let context = validate(router, "interface", &json!({"name":interface}))?;
    let list = cli_token::object_name(acl)?;
    let mut body = json!({"acl":list,"direction":direction.name()});
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
///
/// # Errors
///
/// Returns an error when the rule a removal or property change names is not configured
/// ([`DomainError::FirewallRuleAbsent`]), when the access list or binding cannot be read
/// or does not decode ([`DomainError::Rci`], [`DomainError::InvalidResponse`]), when the
/// plan cannot be rendered ([`DomainError::InvalidResponse`], [`DomainError::InvalidCliToken`]),
/// when the change workflow fails in dispatch or audit, or a rendered line does not bind to
/// its request ([`DomainError::Workflow`]), or when the read-back or a fresh configuration
/// does not show the change ([`DomainError::FirewallVerificationFailed`]).
// NOT cancel-safe: cancelled after the CLI request is sent, the router stays changed
// and the read-back verification never runs.
#[inline]
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

/// Plans `path` with `body` under the `access-list <name>` context.
///
/// # Errors
///
/// Returns [`DomainError::InvalidCliToken`] for an invalid list name and
/// [`DomainError::Validation`] when the catalog refuses a request.
fn contextual(router: &RouterCtx, name: &str, path: &str, body: &Value) -> Result<ChangeOp> {
    let list = cli_token::object_name(name)?;
    Ok(operation(vec![
        validate(router, "access-list", &json!({"name":list}))?,
        validate(router, path, body)?,
    ]))
}

/// A firewall plan of `requests`: management risk, needing `Write`.
const fn operation(requests: Vec<ValidatedRequest>) -> ChangeOp {
    ChangeOp::new(
        requests,
        Vec::new(),
        Risk::Management,
        Permission::Write,
        false,
    )
}

/// Inserts `value` as the member `name` of `fields`.
fn insert(fields: &mut Map<String, Value>, name: &str, value: Value) {
    drop(fields.insert(name.to_owned(), value));
}
