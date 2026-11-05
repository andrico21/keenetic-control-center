//! Leased, catalog-validated, backed-up, verified router changes.
#![expect(
    clippy::absolute_paths,
    clippy::arithmetic_side_effects,
    clippy::duration_suboptimal_units,
    clippy::missing_errors_doc,
    clippy::missing_inline_in_public_items,
    clippy::module_name_repetitions,
    clippy::wildcard_enum_match_arm,
    clippy::renamed_function_params,
    reason = "the plan mandates workflow names and bounded deadline arithmetic; async workflow methods are not inline candidates"
)]

extern crate alloc;

use alloc::{collections::BTreeMap, sync::Arc};
use core::{fmt, time::Duration};
use std::time::{SystemTime, UNIX_EPOCH};

use kcc_catalog::{Catalog, HttpMethod, ValidatedRequest, ValidationIssue};
use kcc_rci::{ConfigKind, RciBody, RciClient, RciError, RciPath};
use secrecy::{ExposeSecret as _, SecretString};
use serde_json::{Value, json};
use tokio::{
    sync::Mutex,
    time::{Instant, sleep},
};

use crate::{
    audit::{Actor, AuditError, AuditEvent, AuditLog},
    backups::{BackupError, BackupStore},
    permissions::{Permission, Role},
    persist::{StateError, StateLock, StateStore},
    registry::{RegistryError, RouterRegistry, authorize},
};

/// Maximum interval in which one automatic pre-change backup is reused.
pub const BACKUP_WINDOW: Duration = Duration::from_secs(30 * 60);
/// Maximum time to wait for an explicit save or commit to settle.
pub const SAVE_TIMEOUT: Duration = Duration::from_secs(30);

/// Router last-change identity used for optimistic concurrency checks.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct LastChange {
    /// Running-configuration checksum.
    pub checksum: String,
    /// Last-changing router agent.
    pub agent: String,
    /// Last-changing router user.
    pub user: String,
    /// Whether running differs from startup.
    pub unsaved: bool,
    /// Raw fail-safe state.
    pub fail_safe: Value,
}

impl LastChange {
    /// Creates a last-change identity.
    #[inline]
    #[must_use]
    pub const fn new(
        checksum: String,
        agent: String,
        user: String,
        unsaved: bool,
        fail_safe: Value,
    ) -> Self {
        Self {
            checksum,
            agent,
            user,
            unsaved,
            fail_safe,
        }
    }
}

/// One read-back expectation.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub struct VerificationSpec {
    /// RCI resource path segments.
    pub path: Vec<String>,
    /// JSON pointer within the decoded response.
    pub field: String,
    /// Expected value at `field`.
    pub expected: Value,
}

impl VerificationSpec {
    /// Creates a read-back expectation.
    #[inline]
    #[must_use]
    pub const fn new(path: Vec<String>, field: String, expected: Value) -> Self {
        Self {
            path,
            field,
            expected,
        }
    }
}

/// One validated mutation request.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub struct ChangeRequest {
    /// Space-separated catalog path.
    pub catalog_path: String,
    /// Slash-separated RCI resource path segments.
    pub rci_path: Vec<String>,
    /// Mutation body.
    pub body: Value,
    /// Read-back expectations.
    pub verify: Vec<VerificationSpec>,
    /// Permission required to execute this operation.
    pub permission: Permission,
    /// Redacted audit parameters.
    pub audit_params: Value,
}

impl ChangeRequest {
    /// Creates a mutation request with read-back and redacted audit data.
    #[inline]
    #[must_use]
    pub const fn new(
        catalog_path: String,
        rci_path: Vec<String>,
        body: Value,
        verify: Vec<VerificationSpec>,
        permission: Permission,
        audit_params: Value,
    ) -> Self {
        Self {
            catalog_path,
            rci_path,
            body,
            verify,
            permission,
            audit_params,
        }
    }
}

/// One catalog-validated CLI parser command.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub struct CliCommand {
    /// Full CLI line sent to the router parser.
    pub line: String,
    /// Catalog validation result proving the operation shape and risk.
    pub validated: ValidatedRequest,
}

impl CliCommand {
    /// Pairs one CLI line with its catalog validation result.
    #[inline]
    #[must_use]
    pub const fn new(line: String, validated: ValidatedRequest) -> Self {
        Self { line, validated }
    }
}

/// One protected CLI parser mutation.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub struct CliChangeRequest {
    /// Ordered catalog-validated parser commands.
    pub commands: Vec<CliCommand>,
    /// Read-back expectations after all commands complete.
    pub verify: Vec<VerificationSpec>,
    /// Permission required to execute this operation.
    pub permission: Permission,
    /// Redacted audit parameters.
    pub audit_params: Value,
}

impl CliChangeRequest {
    /// Creates a protected CLI parser mutation.
    #[inline]
    #[must_use]
    pub const fn new(
        commands: Vec<CliCommand>,
        verify: Vec<VerificationSpec>,
        permission: Permission,
        audit_params: Value,
    ) -> Self {
        Self {
            commands,
            verify,
            permission,
            audit_params,
        }
    }
}

/// Successful CLI parser mutation result.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub struct CliChangeResult {
    /// Ordinary writes always remain unsaved until an explicit save.
    pub unsaved: bool,
    /// Ordered router responses for the parser commands.
    pub responses: Vec<RciBody>,
}

/// Successful mutation result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct ChangeResult {
    /// Ordinary writes always remain unsaved until an explicit save.
    pub unsaved: bool,
}

/// Change workflow failures.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum WorkflowError {
    /// Router lease is held by another actor.
    #[error("router busy: {actor}")]
    RouterBusy {
        /// Actor shown to the user.
        actor: String,
    },
    /// Permission or router scope denied the action.
    #[error("permission denied for router {router}")]
    PermissionDenied {
        /// Router id.
        router: String,
    },
    /// Catalog validation rejected the request.
    #[error("catalog validation failed")]
    CatalogValidation {
        /// Actionable catalog issues.
        issues: Vec<ValidationIssue>,
    },
    /// Another agent changed the router.
    #[error("router configuration changed concurrently by {agent}")]
    Conflict {
        /// Last-changing agent.
        agent: String,
    },
    /// Read-back did not match one expected field.
    #[error("verification failed for {field}")]
    VerificationFailed {
        /// JSON pointer that did not match.
        field: String,
    },
    /// State storage failed.
    #[error(transparent)]
    State(#[from] StateError),
    /// Registry or client setup failed.
    #[error(transparent)]
    Registry(#[from] RegistryError),
    /// Router request failed.
    #[error(transparent)]
    Rci(#[from] RciError),
    /// Backup failed.
    #[error(transparent)]
    Backup(#[from] BackupError),
    /// Audit append failed.
    #[error(transparent)]
    Audit(#[from] AuditError),
    /// Router response had an unusable shape.
    #[error("router returned an invalid last-change response")]
    InvalidResponse,
    /// Explicit save or commit did not settle before the deadline.
    #[error("router save timed out")]
    SaveTimeout,
}

/// Shared services and backup-window state for all change sets.
pub struct ChangeWorkflow {
    /// State store owning cross-process leases.
    state: StateStore,
    /// Router clients.
    registry: Arc<RouterRegistry>,
    /// Encrypted backups.
    backups: Arc<BackupStore>,
    /// Serialized audit appender.
    audit: AuditLog,
    /// Most recent automatic backup time per router.
    backup_times: Mutex<BTreeMap<String, SystemTime>>,
    /// In-process actor labels for better busy errors.
    lease_actors: Mutex<BTreeMap<String, String>>,
}

impl fmt::Debug for ChangeWorkflow {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ChangeWorkflow")
            .field("state", &self.state)
            .field("registry", &self.registry)
            .field("backups", &self.backups)
            .field("audit", &self.audit)
            .finish_non_exhaustive()
    }
}

impl ChangeWorkflow {
    /// Creates a workflow service.
    #[inline]
    #[must_use]
    pub fn new(
        state: StateStore,
        registry: Arc<RouterRegistry>,
        backups: Arc<BackupStore>,
        audit: AuditLog,
    ) -> Arc<Self> {
        Arc::new(Self {
            state,
            registry,
            backups,
            audit,
            backup_times: Mutex::new(BTreeMap::new()),
            lease_actors: Mutex::new(BTreeMap::new()),
        })
    }

    /// Starts a leased change set after checking permission, scope, and concurrency state.
    ///
    /// # Errors
    ///
    /// Returns busy, permission, registry, state, or last-change errors.
    // NOT cancel-safe: cancellation after lease acquisition releases it through Drop.
    pub async fn begin(
        self: &Arc<Self>,
        router: &str,
        actor: Actor,
        role: &Role,
        last_read: Option<LastChange>,
        force: bool,
    ) -> Result<ChangeSet, WorkflowError> {
        authorize(role, Permission::Read, router).map_err(map_permission)?;
        let lease = match self.state.try_lease(router) {
            Ok(lease) => lease,
            Err(StateError::StateLocked { path: _ }) => {
                let actor_name = self
                    .lease_actors
                    .lock()
                    .await
                    .get(router)
                    .cloned()
                    .unwrap_or_else(|| "another process".to_owned());
                return Err(WorkflowError::RouterBusy { actor: actor_name });
            }
            Err(error) => return Err(error.into()),
        };
        drop(
            self.lease_actors
                .lock()
                .await
                .insert(router.to_owned(), actor.id.clone()),
        );
        let client = self.registry.client(router).await?;
        let baseline = read_last_change(&client).await?;
        if !force
            && let Some(previous) = &last_read
            && baseline.checksum != previous.checksum
            && baseline.agent != previous.agent
        {
            drop(self.lease_actors.lock().await.remove(router));
            return Err(WorkflowError::Conflict {
                agent: baseline.agent,
            });
        }
        let info = self.registry.poll_info(router).await?;
        let catalog =
            Catalog::for_router(&info).map_err(|_error| WorkflowError::InvalidResponse)?;
        Ok(ChangeSet {
            workflow: Arc::clone(self),
            router: router.to_owned(),
            actor,
            role: role.clone(),
            client,
            catalog,
            baseline: baseline.clone(),
            expected: baseline,
            backed_up: false,
            force,
            lease: Some(lease),
        })
    }

    /// Checks migration permission and scope for both source and target routers.
    ///
    /// # Errors
    ///
    /// Returns permission denial for either router.
    pub fn authorize_migration(
        role: &Role,
        source: &str,
        target: &str,
    ) -> Result<(), WorkflowError> {
        authorize(role, Permission::Migrate, source).map_err(map_permission)?;
        authorize(role, Permission::Migrate, target).map_err(map_permission)
    }
}

/// One router's leased sequence of writes.
pub struct ChangeSet {
    /// Shared workflow services.
    workflow: Arc<ChangeWorkflow>,
    /// Router id.
    router: String,
    /// Audit actor.
    actor: Actor,
    /// Permission role.
    role: Role,
    /// Shared router client.
    client: Arc<RciClient>,
    /// Router-specific catalog.
    catalog: Catalog,
    /// Last-change state when the set began.
    baseline: LastChange,
    /// Last-change state expected after our own writes.
    expected: LastChange,
    /// Whether this set made its required backup.
    backed_up: bool,
    /// Whether optimistic conflicts are explicitly overridden.
    force: bool,
    /// Cross-process lease.
    lease: Option<StateLock>,
}

impl fmt::Debug for ChangeSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ChangeSet")
            .field("router", &self.router)
            .field("actor", &self.actor)
            .field("baseline", &self.baseline)
            .field("expected", &self.expected)
            .field("backed_up", &self.backed_up)
            .field("force", &self.force)
            .finish_non_exhaustive()
    }
}

impl Drop for ChangeSet {
    fn drop(&mut self) {
        drop(self.lease.take());
        let workflow = Arc::clone(&self.workflow);
        let router = self.router.clone();
        drop(tokio::spawn(async move {
            drop(workflow.lease_actors.lock().await.remove(&router));
        }));
    }
}

impl ChangeSet {
    /// Applies one mutation after catalog validation, backup, conflict check, and read-back.
    ///
    /// # Errors
    ///
    /// Returns validation, conflict, backup, request, verification, or audit errors.
    // NOT cancel-safe: cancellation after transmission may leave an applied unaudited mutation.
    pub async fn apply(&mut self, request: ChangeRequest) -> Result<ChangeResult, WorkflowError> {
        authorize(&self.role, request.permission, &self.router).map_err(map_permission)?;
        let _validated = self
            .catalog
            .validate(&request.catalog_path, HttpMethod::Post, &request.body)
            .map_err(|issues| WorkflowError::CatalogValidation { issues })?;
        self.check_conflict().await?;
        self.ensure_backup().await?;
        let path =
            RciPath::from_segments(&request.rci_path).map_err(|_error| RciError::Validation)?;
        drop(self.client.post(&path, &request.body).await?);
        for verification in &request.verify {
            verify(&self.client, verification).await?;
        }
        self.expected = read_last_change(&self.client).await?;
        let timestamp = unix_seconds();
        let event = AuditEvent::new(timestamp, self.actor.clone(), "router.change".to_owned())
            .with_router(self.router.clone())
            .with_target(request.catalog_path)
            .with_params(request.audit_params)
            .with_result("applied_unsaved".to_owned(), format!("change-{timestamp}"));
        drop(self.workflow.audit.append(event).await?);
        Ok(ChangeResult { unsaved: true })
    }

    /// Applies catalog-validated CLI parser commands under the normal write protections.
    ///
    /// # Errors
    ///
    /// Returns permission, conflict, backup, request, verification, or audit errors.
    // NOT cancel-safe: cancellation after transmission may leave applied unaudited mutations.
    pub async fn apply_cli(
        &mut self,
        request: CliChangeRequest,
    ) -> Result<CliChangeResult, WorkflowError> {
        authorize(&self.role, request.permission, &self.router).map_err(map_permission)?;
        self.check_conflict().await?;
        self.ensure_backup().await?;
        let responses = match request.commands.as_slice() {
            [] => Vec::new(),
            [command] => vec![self.client.parse(&command.line).await?],
            commands => self
                .client
                .parse_batch(commands.iter().map(|command| command.line.as_str()))
                .await?
                .into_iter()
                .map(|response| response.map(RciBody::Json))
                .collect::<Result<Vec<_>, _>>()?,
        };
        for verification in &request.verify {
            verify(&self.client, verification).await?;
        }
        self.expected = read_last_change(&self.client).await?;
        let timestamp = unix_seconds();
        let target = request
            .commands
            .iter()
            .map(|command| command.validated.path.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        let event = AuditEvent::new(
            timestamp,
            self.actor.clone(),
            "router.change_cli".to_owned(),
        )
        .with_router(self.router.clone())
        .with_target(target)
        .with_params(request.audit_params)
        .with_result("applied_unsaved".to_owned(), format!("change-{timestamp}"));
        drop(self.workflow.audit.append(event).await?);
        Ok(CliChangeResult {
            unsaved: true,
            responses,
        })
    }

    /// Explicitly saves running configuration and waits until `unsaved` clears.
    ///
    /// # Errors
    ///
    /// Returns permission, conflict, request, decode, audit, or timeout errors.
    // NOT cancel-safe: cancellation after the save command may leave configuration persisted.
    pub async fn save(&mut self) -> Result<(), WorkflowError> {
        authorize(&self.role, Permission::Save, &self.router).map_err(map_permission)?;
        self.check_conflict().await?;
        drop(self.client.parse("system configuration save").await?);
        self.wait_saved("router.save").await
    }

    /// Explicitly commits a fail-safe change and waits until `unsaved` clears.
    ///
    /// # Errors
    ///
    /// Returns permission, conflict, request, decode, audit, or timeout errors.
    // NOT cancel-safe: cancellation after the commit command may leave configuration persisted.
    pub async fn commit(&mut self) -> Result<(), WorkflowError> {
        authorize(&self.role, Permission::Save, &self.router).map_err(map_permission)?;
        self.check_conflict().await?;
        drop(
            self.client
                .parse("system configuration fail-safe commit")
                .await?,
        );
        self.wait_saved("router.commit").await
    }

    /// Returns the baseline state captured when this change set began.
    #[inline]
    #[must_use]
    pub const fn baseline(&self) -> &LastChange {
        &self.baseline
    }

    /// Reads the current router last-change state while retaining the lease.
    ///
    /// # Errors
    ///
    /// Returns router request or response-shape errors.
    // cancel-safe: the router operation is a read.
    pub async fn current_last_change(&self) -> Result<LastChange, WorkflowError> {
        read_last_change(&self.client).await
    }

    /// Compares the router with the last state observed after this set's own work.
    async fn check_conflict(&self) -> Result<(), WorkflowError> {
        if self.force {
            return Ok(());
        }
        let current = read_last_change(&self.client).await?;
        if current.checksum != self.expected.checksum && current.agent != self.expected.agent {
            return Err(WorkflowError::Conflict {
                agent: current.agent,
            });
        }
        Ok(())
    }

    /// Makes at most one automatic backup per router in the rolling window.
    async fn ensure_backup(&mut self) -> Result<(), WorkflowError> {
        if self.backed_up {
            return Ok(());
        }
        let now = SystemTime::now();
        let needs_backup = self
            .workflow
            .backup_times
            .lock()
            .await
            .get(&self.router)
            .is_none_or(|last| {
                now.duration_since(*last)
                    .is_ok_and(|age| age >= BACKUP_WINDOW)
            });
        if needs_backup {
            let bytes = self.client.download_config(ConfigKind::Startup).await?;
            let text = core::str::from_utf8(bytes.expose_secret())
                .map_err(|_error| WorkflowError::InvalidResponse)?;
            drop(self.workflow.backups.create(
                &self.router,
                "pre-change",
                &SecretString::from(text.to_owned()),
            )?);
            let _previous = self
                .workflow
                .backup_times
                .lock()
                .await
                .insert(self.router.clone(), now);
        }
        self.backed_up = true;
        Ok(())
    }

    /// Polls until save completion and appends the explicit persistence audit event.
    async fn wait_saved(&mut self, action: &str) -> Result<(), WorkflowError> {
        let deadline = Instant::now() + SAVE_TIMEOUT;
        loop {
            let current = read_last_change(&self.client).await?;
            if !current.unsaved {
                self.expected = current;
                let timestamp = unix_seconds();
                let event = AuditEvent::new(timestamp, self.actor.clone(), action.to_owned())
                    .with_router(self.router.clone())
                    .with_result("saved".to_owned(), format!("save-{timestamp}"));
                drop(self.workflow.audit.append(event).await?);
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(WorkflowError::SaveTimeout);
            }
            sleep(Duration::from_millis(250)).await;
        }
    }
}

/// Reads and decodes `show last-change`.
async fn read_last_change(client: &RciClient) -> Result<LastChange, WorkflowError> {
    let path = RciPath::from_segments(["show", "last-change"])
        .map_err(|_error| WorkflowError::InvalidResponse)?;
    let RciBody::Json(response) = client.show(&path, &()).await? else {
        return Err(WorkflowError::InvalidResponse);
    };
    let value = response.value;
    Ok(LastChange {
        checksum: value
            .get("checksum")
            .and_then(Value::as_str)
            .ok_or(WorkflowError::InvalidResponse)?
            .to_owned(),
        agent: value
            .get("agent")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        user: value
            .get("user")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        unsaved: value
            .get("unsaved")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        fail_safe: value.get("fail-safe").cloned().unwrap_or_else(|| json!({})),
    })
}

/// Executes one read-back expectation.
async fn verify(client: &RciClient, spec: &VerificationSpec) -> Result<(), WorkflowError> {
    let path = RciPath::from_segments(&spec.path).map_err(|_error| RciError::Validation)?;
    let actual = match client.show(&path, &()).await? {
        RciBody::Json(response) => response.value,
        RciBody::Text(_) | _ => {
            return Err(WorkflowError::VerificationFailed {
                field: spec.field.clone(),
            });
        }
    };
    if actual.pointer(&spec.field) != Some(&spec.expected) {
        return Err(WorkflowError::VerificationFailed {
            field: spec.field.clone(),
        });
    }
    Ok(())
}

/// Maps registry authorization failures into workflow errors.
fn map_permission(error: RegistryError) -> WorkflowError {
    match error {
        RegistryError::PermissionDenied { router } => WorkflowError::PermissionDenied { router },
        other => WorkflowError::Registry(other),
    }
}

/// Returns current Unix seconds.
fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}
