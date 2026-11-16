//! Named router schedules and their timed actions.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_inline_in_public_items,
    clippy::module_name_repetitions,
    reason = "domain operation names follow the plan; planning and asynchronous reads are not useful inline candidates"
)]

use alloc::{collections::BTreeMap, vec};

mod verification;

use kcc_app::{
    permissions::Permission,
    workflow::{CliChangeRequest, CliCommand as ValidatedCli, VerificationSpec},
};
use kcc_catalog::{HttpMethod, Risk, ValidatedRequest};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    ChangeOp, DomainDescriptor, DomainError, DomainId, OperationDescriptor, Result, RouterCtx,
    cli_token, cli_token::validate as validate_token, read_show,
};

/// One configured schedule.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(default)]
#[non_exhaustive]
pub struct ScheduleState {
    /// Schedule name.
    pub name: Option<String>,
    /// Human-readable description.
    pub description: Option<String>,
    /// Whether the schedule is currently active.
    pub active: Option<bool>,
    /// Unmodelled router fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Schedule action kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ScheduleAction {
    /// Starts the controlled resource.
    Start,
    /// Stops the controlled resource.
    Stop,
}

impl ScheduleAction {
    /// Stable CLI word.
    #[inline]
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Stop => "stop",
        }
    }
}

/// One schedule action with minute, hour, and day-of-week fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct ActionTime {
    /// Action kind.
    pub action: ScheduleAction,
    /// Minute field.
    pub minute: u8,
    /// Hour field.
    pub hour: u8,
    /// Day-of-week bit field.
    pub day_of_week: u8,
}

impl ActionTime {
    /// Creates a schedule action.
    #[inline]
    #[must_use]
    pub const fn new(action: ScheduleAction, minute: u8, hour: u8, day_of_week: u8) -> Self {
        Self {
            action,
            minute,
            hour,
            day_of_week,
        }
    }
}

/// Schedule read inventory.
const READS: &[OperationDescriptor] = &[operation(
    "list",
    "show schedule",
    Risk::Read,
    Permission::Read,
)];

/// Schedule write inventory.
const WRITES: &[OperationDescriptor] = &[
    operation("create", "schedule", Risk::Write, Permission::Write),
    operation(
        "description",
        "schedule description",
        Risk::Write,
        Permission::Write,
    ),
    operation("action", "schedule action", Risk::Write, Permission::Write),
];

/// Schedules domain metadata.
pub const DESCRIPTOR: DomainDescriptor = DomainDescriptor {
    id: DomainId::Schedules,
    read_ops: READS,
    write_ops: WRITES,
    required_components: &[],
};

/// Reads configured schedules.
// cancel-safe: a single read request; cancellation changes nothing on the router.
pub async fn read_schedules(router: &RouterCtx) -> Result<Vec<ScheduleState>> {
    read_show(&router.client, &["show", "schedule"]).await
}

/// Plans schedule creation.
pub fn plan_create(router: &RouterCtx, name: &str) -> Result<ChangeOp> {
    validate_token(name)?;
    Ok(plan(vec![validate(
        router,
        "schedule",
        &json!({"name":name}),
    )?]))
}

/// Plans a schedule description.
pub fn plan_description(router: &RouterCtx, name: &str, description: &str) -> Result<ChangeOp> {
    validate_token(name)?;
    Ok(plan(vec![
        validate(router, "schedule", &json!({"name":name}))?,
        validate(
            router,
            "schedule description",
            &json!({"description":description}),
        )?,
    ]))
}

/// Plans one timed schedule action.
pub fn plan_action(router: &RouterCtx, name: &str, action: ActionTime) -> Result<ChangeOp> {
    validate_token(name)?;
    Ok(plan(vec![
        validate(router, "schedule", &json!({"name":name}))?,
        validate(
            router,
            "schedule action",
            &json!({
                "action":action.action.name(),
                "min":action.minute,
                "hour":action.hour,
                "dow":action.day_of_week,
            }),
        )?,
    ]))
}

/// Converts a schedule plan into a protected workflow request.
pub fn change_request(operation: &ChangeOp) -> Result<CliChangeRequest> {
    let first = operation
        .requests
        .first()
        .ok_or(DomainError::InvalidResponse)?;
    let name = first
        .value()
        .get("name")
        .and_then(Value::as_str)
        .ok_or(DomainError::InvalidResponse)?;
    let mut commands = vec![ValidatedCli::new(format!("schedule {name}"), first.clone())];
    for request in operation.requests.iter().skip(1) {
        let line = match request.path.as_str() {
            "schedule description" => format!(
                "schedule {name} description {}",
                cli_token::quoted_text(
                    request
                        .value()
                        .get("description")
                        .and_then(Value::as_str)
                        .ok_or(DomainError::InvalidResponse)?
                )?
            ),
            "schedule action" => format!(
                "schedule {name} action {} {} {} {}",
                request
                    .value()
                    .get("action")
                    .and_then(Value::as_str)
                    .ok_or(DomainError::InvalidResponse)?,
                request
                    .value()
                    .get("min")
                    .and_then(Value::as_u64)
                    .ok_or(DomainError::InvalidResponse)?,
                request
                    .value()
                    .get("hour")
                    .and_then(Value::as_u64)
                    .ok_or(DomainError::InvalidResponse)?,
                request
                    .value()
                    .get("dow")
                    .and_then(Value::as_u64)
                    .ok_or(DomainError::InvalidResponse)?
            ),
            _ => return Err(DomainError::InvalidResponse),
        };
        commands.push(ValidatedCli::new(line, request.clone()));
    }
    Ok(CliChangeRequest::new(
        commands,
        vec![VerificationSpec::collection(
            vec!["show".to_owned(), "rc".to_owned()],
            "/schedule".to_owned(),
            verification::expected(operation, name)?,
            true,
        )],
        Permission::Write,
        json!({"operation":"schedule","name":name}),
    ))
}

/// Builds one operation descriptor.
const fn operation(
    name: &'static str,
    catalog_path: &'static str,
    risk: Risk,
    permission: Permission,
) -> OperationDescriptor {
    OperationDescriptor {
        name,
        catalog_path,
        risk,
        permission,
        persists_immediately: false,
    }
}

/// Validates one catalog request.
fn validate(router: &RouterCtx, path: &str, body: &Value) -> Result<ValidatedRequest> {
    router
        .catalog
        .validate(path, HttpMethod::Post, body)
        .map_err(|issues| DomainError::Validation { issues })
}

/// Constructs the shared schedule operation shape.
const fn plan(requests: Vec<ValidatedRequest>) -> ChangeOp {
    ChangeOp::new(requests, Vec::new(), Risk::Write, Permission::Write, false)
}
