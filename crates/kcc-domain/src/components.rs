//! Firmware components, update policy, and rebooting component commits.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_inline_in_public_items,
    clippy::module_name_repetitions,
    reason = "domain operation names follow the plan; asynchronous router jobs are not useful inline candidates"
)]

use alloc::{collections::BTreeMap, sync::Arc, vec};
use core::result::Result as CoreResult;

use kcc_app::{
    jobs::{JobError, JobRunner},
    permissions::{Permission, Role},
    registry::{RegistryError, RouterRegistry},
    workflow::{ChangeSet, CliChangeRequest, CliCommand as ValidatedCli, VerificationSpec},
};
use kcc_catalog::{Catalog, HttpMethod, Risk};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    ChangeOp, DomainDescriptor, DomainError, DomainId, OperationDescriptor, Result, RouterCtx,
    cli_token, descriptor::operation, read_show, verification,
};

mod commit;

/// One component returned by `show components list`.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(default)]
#[non_exhaustive]
pub struct ComponentState {
    /// Component name.
    pub name: Option<String>,
    /// Whether the component is installed.
    pub installed: Option<bool>,
    /// Unmodelled router fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Staged component changes.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(default)]
#[non_exhaustive]
pub struct PendingComponents {
    /// Components staged for installation.
    pub install: Vec<String>,
    /// Components staged for removal.
    pub remove: Vec<String>,
    /// Unmodelled router fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Structured before/after component-commit progress.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[non_exhaustive]
pub struct CommitProgress {
    /// Progress phase.
    pub phase: String,
    /// Firmware title before commit.
    pub before_firmware: Option<String>,
    /// Firmware title after commit, once detected.
    pub after_firmware: Option<String>,
    /// Components before commit.
    pub before_components: Vec<String>,
    /// Components after commit, once detected.
    pub after_components: Vec<String>,
}

/// Component queue action.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum QueueAction {
    /// Stage installation.
    Install,
    /// Stage removal.
    Remove,
}

/// Component read inventory.
const READS: &[OperationDescriptor] = &[
    operation("list", "components list", Risk::Read, Permission::Read),
    operation(
        "pending",
        "components preview",
        Risk::Read,
        Permission::Read,
    ),
];

/// Component write inventory.
const WRITES: &[OperationDescriptor] = &[
    operation(
        "check_update",
        "components check-update",
        Risk::Write,
        Permission::Write,
    ),
    operation(
        "install",
        "components install",
        Risk::Write,
        Permission::Write,
    ),
    operation(
        "remove",
        "components remove",
        Risk::Write,
        Permission::Write,
    ),
    operation(
        "commit",
        "components commit",
        Risk::Destructive,
        Permission::Destructive,
    ),
    operation(
        "auto_update_channel",
        "components auto-update channel",
        Risk::Write,
        Permission::Write,
    ),
    operation(
        "auto_update_schedule",
        "components auto-update schedule",
        Risk::Write,
        Permission::Write,
    ),
];

/// Components domain metadata.
pub const DESCRIPTOR: DomainDescriptor = DomainDescriptor {
    id: DomainId::Components,
    read_ops: READS,
    write_ops: WRITES,
    required_components: &[],
};

/// Reads installed components.
// cancel-safe: a single read request; cancellation changes nothing on the router.
pub async fn read_components(router: &RouterCtx) -> Result<Vec<ComponentState>> {
    read_show(&router.client, &["show", "components", "list"]).await
}

/// Reads staged component changes.
// cancel-safe: a single read request; cancellation changes nothing on the router.
pub async fn read_pending(router: &RouterCtx) -> Result<PendingComponents> {
    read_show(&router.client, &["show", "components", "pending"]).await
}

/// Plans an update-availability check.
pub fn plan_check_update(router: &RouterCtx) -> Result<ChangeOp> {
    plan_cli(router, "components check-update", &json!({}), Risk::Write)
}

/// Plans one component installation or removal queue operation.
pub fn plan_queue(router: &RouterCtx, action: QueueAction, component: &str) -> Result<ChangeOp> {
    validate_token(component)?;
    let path = match action {
        QueueAction::Install => "components install",
        QueueAction::Remove => "components remove",
    };
    plan_cli(router, path, &json!({"component":component}), Risk::Write)
}

/// Plans the automatic-update channel.
pub fn plan_auto_update_channel(router: &RouterCtx, channel: &str) -> Result<ChangeOp> {
    validate_token(channel)?;
    plan_cli(
        router,
        "components auto-update channel",
        &json!({"channel":channel}),
        Risk::Write,
    )
}

/// Plans the automatic-update schedule.
pub fn plan_auto_update_schedule(router: &RouterCtx, schedule: &str) -> Result<ChangeOp> {
    validate_token(schedule)?;
    plan_cli(
        router,
        "components auto-update schedule",
        &json!({"schedule":schedule}),
        Risk::Write,
    )
}

/// Converts a non-terminal component plan into a protected workflow request.
pub fn change_request(operation: &ChangeOp) -> Result<CliChangeRequest> {
    let request = operation
        .requests
        .first()
        .ok_or(DomainError::InvalidResponse)?;
    let argument = request
        .value()
        .as_object()
        .into_iter()
        .flatten()
        .find_map(|(key, value)| (key != "no").then_some(value))
        .and_then(|value| match value {
            Value::String(text) => Some(text.as_str()),
            Value::Null
            | Value::Bool(_)
            | Value::Number(_)
            | Value::Array(_)
            | Value::Object(_) => None,
        });
    let line = argument.map_or_else(
        || request.path.clone(),
        |value| format!("{} {value}", request.path),
    );
    verification::complete(CliChangeRequest::new(
        vec![ValidatedCli::new(line, request.clone())],
        if matches!(
            request.path.as_str(),
            "components install" | "components remove"
        ) {
            vec![VerificationSpec::collection(
                vec![
                    "show".to_owned(),
                    "components".to_owned(),
                    "pending".to_owned(),
                ],
                format!(
                    "/{}",
                    request
                        .path
                        .strip_prefix("components ")
                        .ok_or(DomainError::InvalidResponse)?
                ),
                json!(argument.ok_or(DomainError::InvalidResponse)?),
                true,
            )]
        } else {
            Vec::new()
        },
        operation.permission,
        json!({"operation":request.path}),
    ))
}

/// Starts a confirmed destructive component commit job.
// NOT cancel-safe: once spawned, the commit job (which reboots the router) runs on without its id
// reaching the caller; cancelled inside job start, the router's write-job slot can stay taken.
pub async fn start_commit_job(
    jobs: &Arc<JobRunner>,
    registry: Arc<RouterRegistry>,
    router_name: String,
    role: &Role,
    changes: ChangeSet,
    catalog: &Catalog,
    confirmed: bool,
) -> CoreResult<String, CommitError> {
    commit::start(
        jobs,
        registry,
        router_name,
        role,
        changes,
        catalog,
        confirmed,
    )
    .await
}

/// Component commit start failures.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CommitError {
    /// The caller did not explicitly confirm rebooting component commit.
    #[error("component commit requires explicit confirmation")]
    ConfirmationRequired,
    /// Domain planning failed.
    #[error(transparent)]
    Domain(#[from] DomainError),
    /// Permission or router setup failed.
    #[error(transparent)]
    Registry(#[from] RegistryError),
    /// Job persistence or exclusivity failed.
    #[error(transparent)]
    Job(JobError),
}

/// Plans one catalog-validated component CLI operation.
fn plan_cli(router: &RouterCtx, path: &str, body: &Value, risk: Risk) -> Result<ChangeOp> {
    let validated = router
        .catalog
        .validate(path, HttpMethod::Post, body)
        .map_err(|issues| DomainError::Validation { issues })?;
    Ok(ChangeOp::new(
        vec![validated],
        Vec::new(),
        risk,
        Permission::Write,
        false,
    ))
}

/// Rejects values that cannot be represented as one unquoted router CLI token.
fn validate_token(value: &str) -> Result<()> {
    cli_token::validate(value)
}
