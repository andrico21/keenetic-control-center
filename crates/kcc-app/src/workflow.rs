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
    clippy::pub_use,
    reason = "the plan mandates workflow names and bounded deadline arithmetic; async workflow methods are not inline candidates"
)]

extern crate alloc;

use alloc::{collections::BTreeMap, sync::Arc};
use core::{fmt, time::Duration};
use std::time::{SystemTime, UNIX_EPOCH};

use kcc_catalog::{Catalog, HttpMethod, Risk, SecretValue, ValidatedRequest, ValidationIssue};
use kcc_rci::{
    ConfigKind, RciBody, RciClient, RciError, RciPath, RciResponse, RouterUrl, SecretBytes,
    auth::Credentials,
};
use secrecy::{ExposeSecret as _, SecretString};
use serde::Serialize;
use serde_json::{Value, json};

#[path = "workflow_batch.rs"]
mod batch;
#[path = "workflow_cli.rs"]
mod cli;
#[path = "workflow_output.rs"]
mod output;
#[path = "workflow_replay.rs"]
mod replay;
#[path = "workflow_verify.rs"]
mod verification;
pub use cli::command::{CliCommand, SecretCommandError};
pub use replay::{ReplayCompletionError, ReplayOutcome, ReplayPolicy, ReplayResult};
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
#[derive(Clone, Debug, PartialEq, Serialize)]
#[non_exhaustive]
pub struct VerificationSpec {
    /// Optional named collection row selected before reading `field`.
    pub row: Option<(String, Value)>,
    /// RCI resource path segments.
    pub path: Vec<String>,
    /// JSON pointer within the decoded response.
    pub field: String,
    /// Expected value at `field`.
    pub expected: Value,
    /// Optional secret-safe presence or byte-length check.
    pub predicate: Option<PresencePredicate>,
}

/// Read-back checks that never compare secret material.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub enum PresencePredicate {
    /// A named configuration credential has a bounded nonempty protected payload.
    ConfigSecret,
    /// The canonical running configuration contains the expected CLI token sequence.
    ConfigCommand,
    /// The canonical running configuration excludes the expected CLI token sequence.
    ConfigCommandAbsent,
    /// The field is absent from a successfully read configuration object.
    Absent,
    /// The selected collection contains the expected non-secret fields.
    Contains,
    /// The readable collection contains no row matching the expected non-secret fields.
    Excludes,
    /// The pointer exists and is not null.
    Present,
    /// The pointer contains a nonempty string.
    NonEmpty,
    /// String byte length is inside an inclusive range.
    LengthRange {
        /// Inclusive lower bound.
        minimum: usize,
        /// Inclusive upper bound.
        maximum: usize,
    },
    /// A true presence marker, or a string with an inclusive byte-length range.
    MarkerOrLengthRange {
        /// Inclusive lower bound when the router returns a string.
        minimum: usize,
        /// Inclusive upper bound when the router returns a string.
        maximum: usize,
    },
}

impl VerificationSpec {
    /// Matches a non-secret row in a readable collection, independently of row order.
    #[inline]
    #[must_use]
    pub const fn collection(
        path: Vec<String>,
        field: String,
        expected: Value,
        present: bool,
    ) -> Self {
        Self {
            row: None,
            path,
            field,
            expected,
            predicate: Some(if present {
                PresencePredicate::Contains
            } else {
                PresencePredicate::Excludes
            }),
        }
    }

    /// Creates a read-back expectation.
    #[inline]
    #[must_use]
    pub const fn new(path: Vec<String>, field: String, expected: Value) -> Self {
        Self {
            row: None,
            path,
            field,
            expected,
            predicate: None,
        }
    }

    /// Creates a secret-safe JSON pointer presence or byte-length expectation.
    #[inline]
    #[must_use]
    pub const fn presence(path: Vec<String>, field: String, predicate: PresencePredicate) -> Self {
        Self {
            row: None,
            path,
            field,
            expected: Value::Null,
            predicate: Some(predicate),
        }
    }
}

/// One validated mutation request.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[non_exhaustive]
pub struct ChangeRequest {
    /// Space-separated catalog path.
    pub catalog_path: String,
    /// Slash-separated RCI resource path segments.
    pub rci_path: Vec<String>,
    /// Mutation body.
    pub body: SecretValue,
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
    pub fn new(
        catalog_path: String,
        rci_path: Vec<String>,
        body: Value,
        verify: Vec<VerificationSpec>,
        permission: Permission,
        mut audit_params: Value,
    ) -> Self {
        let protected_body = SecretValue::new(&catalog_path, body);
        protected_body.scrub(&mut audit_params);
        Self {
            catalog_path,
            rci_path,
            body: protected_body,
            verify,
            permission,
            audit_params,
        }
    }
}

/// One validated deletion request.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[non_exhaustive]
pub struct DeleteRequest {
    /// Space-separated catalog path.
    pub catalog_path: String,
    /// Slash-separated RCI resource path segments.
    pub rci_path: Vec<String>,
    /// Serialized deletion query parameters.
    pub query: SecretValue,
    /// Read-back expectations.
    pub verify: Vec<VerificationSpec>,
    /// Permission required to execute this operation.
    pub permission: Permission,
    /// Redacted audit parameters.
    pub audit_params: Value,
}

impl DeleteRequest {
    /// Creates a deletion request with read-back and redacted audit data.
    #[inline]
    #[must_use]
    pub fn new(
        catalog_path: String,
        rci_path: Vec<String>,
        query: Value,
        verify: Vec<VerificationSpec>,
        permission: Permission,
        mut audit_params: Value,
    ) -> Self {
        let protected_query = SecretValue::new(&catalog_path, query);
        protected_query.scrub(&mut audit_params);
        Self {
            catalog_path,
            rci_path,
            query: protected_query,
            verify,
            permission,
            audit_params,
        }
    }
}

/// One root RCI batch item paired with its catalog validation result.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[non_exhaustive]
pub struct BatchItem {
    /// Root RCI object sent to the router.
    pub value: SecretValue,
    /// Catalog validation result proving the operation shape and risk.
    pub validated: ValidatedRequest,
}

impl BatchItem {
    /// Pairs one root RCI object with its catalog validation result.
    #[inline]
    #[must_use]
    pub fn new(value: Value, validated: ValidatedRequest) -> Self {
        Self {
            value: SecretValue::new("", value),
            validated,
        }
    }
}

/// One protected root RCI batch mutation.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[non_exhaustive]
pub struct BatchChangeRequest {
    /// Ordered catalog-validated root RCI items.
    pub items: Vec<BatchItem>,
    /// Read-back expectations after all items complete.
    pub verify: Vec<VerificationSpec>,
    /// Permission required to execute this operation.
    pub permission: Permission,
    /// Redacted audit parameters.
    pub audit_params: Value,
}

impl BatchChangeRequest {
    /// Creates a protected root RCI batch mutation.
    #[inline]
    #[must_use]
    pub fn new(
        items: Vec<BatchItem>,
        verify: Vec<VerificationSpec>,
        permission: Permission,
        mut audit_params: Value,
    ) -> Self {
        for item in &items {
            item.value.scrub(&mut audit_params);
        }
        Self {
            items,
            verify,
            permission,
            audit_params,
        }
    }
}

/// Root RCI batch result, including item-level refusals.
#[derive(Debug)]
#[non_exhaustive]
pub struct BatchChangeResult {
    /// Successful items containing changes, excluding read answers.
    pub applied_changes: usize,
    /// Successful ordinary writes remain unsaved until an explicit save.
    pub unsaved: bool,
    /// Whether all successful items were persisted immediately, with at least one success.
    pub persists_immediately: bool,
    /// Persisted leaf paths from successful items only.
    pub persisted_paths: Vec<String>,
    /// Ordered per-item router responses, including item-level failures.
    pub responses: Vec<Result<RciResponse, RciError>>,
}

/// One protected CLI parser mutation.
#[derive(Clone, Debug, PartialEq, Serialize)]
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
    pub fn new(
        commands: Vec<CliCommand>,
        verify: Vec<VerificationSpec>,
        permission: Permission,
        mut audit_params: Value,
    ) -> Self {
        for command in &commands {
            command.secrets().scrub(&mut audit_params);
        }
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

/// One protected terminal CLI parser mutation.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[non_exhaustive]
pub struct TerminalCliChangeRequest {
    /// Ordered catalog-validated parser commands.
    pub commands: Vec<CliCommand>,
    /// Permission required to execute this operation.
    pub permission: Permission,
    /// Redacted audit parameters.
    pub audit_params: Value,
}

impl TerminalCliChangeRequest {
    /// Creates a protected terminal CLI parser mutation.
    #[inline]
    #[must_use]
    pub fn new(commands: Vec<CliCommand>, permission: Permission, mut audit_params: Value) -> Self {
        for command in &commands {
            command.secrets().scrub(&mut audit_params);
        }
        Self {
            commands,
            permission,
            audit_params,
        }
    }
}

/// Successful terminal CLI parser mutation result.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub struct TerminalCliChangeResult {
    /// Ordered router responses received before the session became unreachable.
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
    /// Secret CLI construction failed before dispatch.
    #[error(transparent)]
    SecretCommand(#[from] SecretCommandError),
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
        self.begin_with_client(router, actor, role, last_read, force, None)
            .await
    }

    /// Starts a migration lease, permitting explicitly requested factory setup.
    ///
    /// # Errors
    /// Returns authorization, lease, authentication, or inventory failures.
    // NOT cancel-safe: cancellation releases the acquired lease.
    pub async fn begin_migration(
        self: &Arc<Self>,
        router: &str,
        actor: Actor,
        role: &Role,
    ) -> Result<ChangeSet, WorkflowError> {
        let client = self.registry.bootstrap_client(role, router).await?;
        self.begin_with_client(router, actor, role, None, false, Some(client))
            .await
    }

    /// Acquires the ordinary lease using a caller-selected migration client when supplied.
    // NOT cancel-safe: cancellation releases the acquired lease.
    async fn begin_with_client(
        self: &Arc<Self>,
        router: &str,
        actor: Actor,
        role: &Role,
        last_read: Option<LastChange>,
        force: bool,
        selected: Option<Arc<RciClient>>,
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
        let migration = selected.is_some();
        let client = match selected {
            Some(client) => client,
            None => self.registry.client(router).await?,
        };
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
        let info = if migration {
            client.detect().await?
        } else {
            self.registry.poll_info(router).await?
        };
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

    /// The encrypted backup store this workflow writes its automatic backups to; a
    /// migration reads its stored backup sources from it.
    #[inline]
    #[must_use]
    pub const fn backups(&self) -> &Arc<BackupStore> {
        &self.backups
    }

    /// The state directory owner holding this workflow's leases; front ends keep their
    /// own per-router records beside them.
    #[inline]
    #[must_use]
    pub const fn state(&self) -> &StateStore {
        &self.state
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
    /// Rejects any change since this lease's last successful write, including the same agent.
    ///
    /// # Errors
    /// Returns a conflict or read failure without transmitting a mutation.
    // cancel-safe: this operation only reads router state.
    pub async fn ensure_unchanged(&self) -> Result<(), WorkflowError> {
        let current = read_last_change(&self.client).await?;
        if current.checksum != self.expected.checksum {
            return Err(WorkflowError::Conflict {
                agent: current.agent,
            });
        }
        Ok(())
    }

    /// Restores the original transport and credential after router-side rollback.
    ///
    /// # Errors
    /// Returns authorization, original-origin reachability, or credential persistence errors.
    // NOT cancel-safe: registry persistence follows a successful original-client probe.
    pub async fn restore_connection(
        &mut self,
        original: Arc<RciClient>,
    ) -> Result<(), WorkflowError> {
        authorize(&self.role, Permission::Migrate, &self.router).map_err(map_permission)?;
        let expected = read_last_change(&original).await?;
        let credentials = original.credentials();
        self.workflow
            .registry
            .transition(&self.router, Arc::clone(&original), Some(&credentials))
            .await?;
        self.client = original;
        self.expected = expected;
        Ok(())
    }

    /// Returns the current client while this change set retains the write lease.
    #[inline]
    #[must_use]
    pub fn client(&self) -> Arc<RciClient> {
        Arc::clone(&self.client)
    }

    /// Reconnects using a confirmed origin and optional replacement primary credential.
    ///
    /// # Errors
    /// Returns permission, authentication, registry persistence, or read-back errors.
    // NOT cancel-safe: the router credential may already have changed before this transition.
    pub async fn reconnect(
        &mut self,
        url: RouterUrl,
        credentials: Option<Credentials>,
    ) -> Result<(), WorkflowError> {
        authorize(&self.role, Permission::Migrate, &self.router).map_err(map_permission)?;
        let client = Arc::new(self.client.retarget(url, credentials.clone()).await?);
        let expected = read_last_change(&client).await?;
        self.workflow
            .registry
            .transition(&self.router, Arc::clone(&client), credentials.as_ref())
            .await?;
        self.client = client;
        self.expected = expected;
        Ok(())
    }

    /// Uploads startup configuration through the leased, backed-up destructive workflow.
    ///
    /// # Errors
    /// Returns permission, conflict, backup, upload, or audit failures.
    // NOT cancel-safe: a transmitted upload can replace startup configuration before cancellation.
    pub async fn upload_startup(&mut self, bytes: &SecretBytes) -> Result<(), WorkflowError> {
        self.prepare_cli(Permission::Destructive).await?;
        drop(self.client.upload_startup_config(bytes).await?);
        self.audit_cli(
            &[],
            "router.raw_restore_upload",
            json!({}),
            "startup_replaced",
        )
        .await
    }

    /// Replays migration commands while retaining partial results after a later failure.
    ///
    /// # Errors
    ///
    /// Returns failures before dispatch; subsequent failures remain in the returned result.
    // NOT cancel-safe: a transmitted line may apply before cancellation.
    pub async fn replay(
        &mut self,
        commands: &[CliCommand],
        policy: ReplayPolicy,
    ) -> Result<ReplayResult, WorkflowError> {
        replay::run(self, commands, policy).await
    }

    /// Applies one mutation after catalog validation, backup, conflict check, and read-back.
    ///
    /// # Errors
    ///
    /// Returns validation, conflict, backup, request, verification, or audit errors.
    // NOT cancel-safe: cancellation after transmission may leave an applied unaudited mutation.
    pub async fn apply(&mut self, request: ChangeRequest) -> Result<ChangeResult, WorkflowError> {
        authorize(&self.role, request.permission, &self.router).map_err(map_permission)?;
        let wire = request.body.expose_for_send();
        let validated = self
            .catalog
            .validate(
                &request.catalog_path,
                HttpMethod::Post,
                wire.expose_secret(),
            )
            .map_err(|issues| WorkflowError::CatalogValidation { issues })?;
        self.check_conflict().await?;
        self.ensure_backup().await?;
        let path =
            RciPath::from_segments(&request.rci_path).map_err(|_error| RciError::Validation)?;
        drop(
            self.client
                .post(&path, wire.expose_secret())
                .await
                .map_err(|error| scrub_error(validated.protected_value(), error))?,
        );
        for verification in &request.verify {
            verify(&self.client, verification).await?;
        }
        self.expected = read_last_change(&self.client).await?;
        let timestamp = unix_seconds();
        let mut audit_params = request.audit_params;
        validated.protected_value().scrub(&mut audit_params);
        let event = AuditEvent::new(timestamp, self.actor.clone(), "router.change".to_owned())
            .with_router(self.router.clone())
            .with_target(request.catalog_path)
            .with_params(audit_params)
            .with_result(
                if validated.risk == Risk::Read {
                    "success"
                } else {
                    applied_outcome(validated.persists_immediately)
                }
                .to_owned(),
                format!("change-{timestamp}"),
            );
        drop(self.workflow.audit.append(event).await?);
        Ok(ChangeResult {
            unsaved: !validated.ordinary_paths.is_empty(),
        })
    }

    /// Applies one deletion after catalog validation, backup, conflict check, and read-back.
    ///
    /// # Errors
    ///
    /// Returns validation, conflict, backup, request, verification, or audit errors.
    // NOT cancel-safe: cancellation after transmission may leave an applied unaudited deletion.
    pub async fn apply_delete(
        &mut self,
        request: DeleteRequest,
    ) -> Result<ChangeResult, WorkflowError> {
        authorize(&self.role, request.permission, &self.router).map_err(map_permission)?;
        let wire = request.query.expose_for_send();
        let validated = self
            .catalog
            .validate(
                &request.catalog_path,
                HttpMethod::Delete,
                wire.expose_secret(),
            )
            .map_err(|issues| WorkflowError::CatalogValidation { issues })?;
        if validated.has_secrets() {
            return Err(RciError::Validation.into());
        }
        self.check_conflict().await?;
        self.ensure_backup().await?;
        let path =
            RciPath::from_segments(&request.rci_path).map_err(|_error| RciError::Validation)?;
        drop(
            self.client
                .delete(&path, wire.expose_secret())
                .await
                .map_err(|error| scrub_error(validated.protected_value(), error))?,
        );
        for verification in &request.verify {
            verify(&self.client, verification).await?;
        }
        self.expected = read_last_change(&self.client).await?;
        let timestamp = unix_seconds();
        let event = AuditEvent::new(
            timestamp,
            self.actor.clone(),
            "router.change_delete".to_owned(),
        )
        .with_router(self.router.clone())
        .with_target(request.catalog_path)
        .with_params(request.audit_params)
        .with_result(
            applied_outcome(validated.persists_immediately).to_owned(),
            format!("change-{timestamp}"),
        );
        drop(self.workflow.audit.append(event).await?);
        Ok(ChangeResult { unsaved: true })
    }

    /// Applies catalog-validated root RCI items under the normal write protections.
    ///
    /// # Errors
    ///
    /// Returns permission, conflict, backup, request, verification, or audit errors.
    // NOT cancel-safe: cancellation after transmission may leave applied unaudited mutations.
    pub async fn apply_batch(
        &mut self,
        request: BatchChangeRequest,
    ) -> Result<BatchChangeResult, WorkflowError> {
        authorize(&self.role, request.permission, &self.router).map_err(map_permission)?;
        for item in &request.items {
            let body = item.value.expose_for_send();
            drop(
                self.catalog
                    .validate("", HttpMethod::Post, body.expose_secret())
                    .map_err(|issues| WorkflowError::CatalogValidation { issues })?,
            );
        }
        self.check_conflict().await?;
        self.ensure_backup().await?;
        let wire = request
            .items
            .iter()
            .map(|item| item.value.expose_for_send())
            .collect::<Vec<_>>();
        let values = wire
            .iter()
            .map(|value| value.expose_secret().clone())
            .collect();
        let mut responses = self.client.batch(values).await.map_err(|mut error| {
            for item in &request.items {
                error = scrub_error(&item.value, error);
            }
            error
        })?;
        for response in &mut responses {
            for item in &request.items {
                match response {
                    Ok(value) => scrub_response(&item.value, value),
                    Err(error) => scrub_error_mut(&item.value, error),
                }
            }
        }
        for verification in &request.verify {
            verify(&self.client, verification).await?;
        }
        self.expected = read_last_change(&self.client).await?;
        let timestamp = unix_seconds();
        let target = request
            .items
            .iter()
            .map(|item| item.validated.path.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        let mut audit_params = request.audit_params;
        for item in &request.items {
            item.value.scrub(&mut audit_params);
        }
        let completion = batch::completion(&request.items, &responses);
        let outcome = completion.outcome();
        if completion.failed != 0 {
            audit_params = json!({
                "error":"router_rejected",
                "succeeded":completion.succeeded,
                "failed":completion.failed,
            });
        }
        let event = AuditEvent::new(
            timestamp,
            self.actor.clone(),
            "router.change_batch".to_owned(),
        )
        .with_router(self.router.clone())
        .with_target(target)
        .with_params(audit_params)
        .with_result(outcome.to_owned(), format!("change-{timestamp}"));
        drop(self.workflow.audit.append(event).await?);
        Ok(BatchChangeResult {
            applied_changes: completion.applied_changes,
            unsaved: completion.unsaved,
            persists_immediately: completion.persists_immediately,
            persisted_paths: completion.persisted_paths,
            responses,
        })
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
        for command in &request.commands {
            drop(command.expose_for_send()?);
        }
        self.prepare_cli(request.permission).await?;
        let responses = self.dispatch_cli(&request.commands).await?;
        for verification in &request.verify {
            verify(&self.client, verification).await?;
        }
        self.expected = read_last_change(&self.client).await?;
        let unsaved = request
            .commands
            .iter()
            .any(|command| !command.validated().ordinary_paths.is_empty());
        let persists_immediately = !unsaved
            && request
                .commands
                .iter()
                .any(|command| !command.validated().persisted_paths.is_empty());
        self.audit_cli(
            &request.commands,
            "router.change_cli",
            request.audit_params,
            if !unsaved && !persists_immediately {
                "success"
            } else {
                applied_outcome(persists_immediately)
            },
        )
        .await?;
        Ok(CliChangeResult { unsaved, responses })
    }

    /// Applies terminal CLI parser commands without requiring the router to remain reachable.
    ///
    /// # Errors
    ///
    /// Returns permission, conflict, backup, request, or audit errors.
    // NOT cancel-safe: cancellation after transmission may leave an applied unaudited mutation.
    pub async fn apply_cli_terminal(
        &mut self,
        request: TerminalCliChangeRequest,
    ) -> Result<TerminalCliChangeResult, WorkflowError> {
        for command in &request.commands {
            drop(command.expose_for_send()?);
        }
        self.prepare_cli(request.permission).await?;
        let responses = self.dispatch_cli(&request.commands).await?;
        self.audit_cli(
            &request.commands,
            "router.change_cli_terminal",
            request.audit_params,
            "applied_state_unknown",
        )
        .await?;
        Ok(TerminalCliChangeResult { responses })
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

    /// Applies authorization, conflict, and backup preflight for CLI mutations.
    // NOT cancel-safe: cancellation can interrupt backup preparation.
    async fn prepare_cli(&mut self, permission: Permission) -> Result<(), WorkflowError> {
        authorize(&self.role, permission, &self.router).map_err(map_permission)?;
        self.check_conflict().await?;
        self.ensure_backup().await
    }

    /// Sends CLI commands and preserves their ordered responses.
    // NOT cancel-safe: dispatched commands may apply before cancellation.
    async fn dispatch_cli(&self, commands: &[CliCommand]) -> Result<Vec<RciBody>, WorkflowError> {
        let lines = commands
            .iter()
            .map(CliCommand::expose_for_send)
            .collect::<Result<Vec<_>, _>>()?;
        let scrub_failure = |mut error| {
            for command in commands {
                error = scrub_error(command.secrets(), error);
            }
            WorkflowError::Rci(error)
        };
        let mut responses = match lines.as_slice() {
            [] => Ok(Vec::new()),
            [line] => Ok(vec![self.client.parse(line).await.map_err(scrub_failure)?]),
            many => self
                .client
                .parse_batch(many.iter().map(|line| line.as_str()))
                .await
                .map_err(scrub_failure)?
                .into_iter()
                .map(|response| response.map(RciBody::Json).map_err(scrub_failure))
                .collect(),
        }?;
        for response in &mut responses {
            for command in commands {
                match response {
                    RciBody::Json(value) => scrub_response(command.secrets(), value),
                    RciBody::Text(text) => *text = command.secrets().scrub_text(text),
                    _ => return Err(WorkflowError::InvalidResponse),
                }
            }
        }
        Ok(responses)
    }

    /// Appends a CLI mutation audit event without contacting the router.
    // NOT cancel-safe: the writer can append after cancellation.
    async fn audit_cli(
        &self,
        commands: &[CliCommand],
        action: &str,
        mut audit_params: Value,
        outcome: &str,
    ) -> Result<(), WorkflowError> {
        let timestamp = unix_seconds();
        for command in commands {
            command.secrets().scrub(&mut audit_params);
        }
        let target = commands
            .iter()
            .map(|command| command.validated().path.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        let event = AuditEvent::new(timestamp, self.actor.clone(), action.to_owned())
            .with_router(self.router.clone())
            .with_target(target)
            .with_params(audit_params)
            .with_result(outcome.to_owned(), format!("change-{timestamp}"));
        drop(self.workflow.audit.append(event).await?);
        Ok(())
    }

    /// Compares the router with the last state observed after this set's own work.
    // cancel-safe: only reads router state.
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
    // NOT cancel-safe: cancellation can interrupt backup preparation.
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
    // NOT cancel-safe: the save may complete before the audit append.
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
// cancel-safe: only reads router state.
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
// cancel-safe: only reads router state.
async fn verify(client: &RciClient, spec: &VerificationSpec) -> Result<(), WorkflowError> {
    if matches!(
        spec.predicate,
        Some(
            PresencePredicate::ConfigCommand
                | PresencePredicate::ConfigCommandAbsent
                | PresencePredicate::ConfigSecret
        )
    ) {
        return verification::configuration(client, spec).await;
    }
    let path = RciPath::from_segments(&spec.path).map_err(|_error| RciError::Validation)?;
    let configuration = spec.path.starts_with(&["show".to_owned(), "rc".to_owned()]);
    let readback = if configuration {
        let tree = spec
            .path
            .iter()
            .skip(2)
            .rev()
            .fold(json!({}), |child, segment| json!({segment:child}));
        client.show_rc(tree).await?
    } else {
        client.show(&path, &()).await?
    };
    let actual = match readback {
        RciBody::Json(response) => response.value,
        RciBody::Text(_) | _ => {
            return Err(WorkflowError::VerificationFailed {
                field: spec.field.clone(),
            });
        }
    };
    let selected = if configuration {
        spec.path
            .iter()
            .skip(2)
            .fold(actual.pointer("/show/rc"), |parent, segment| {
                parent?.get(segment)
            })
    } else {
        Some(&actual)
    };
    let selected_row = match &spec.row {
        Some((key, expected)) => selected
            .and_then(Value::as_array)
            .and_then(|rows| rows.iter().find(|row| row.get(key) == Some(expected))),
        None => selected,
    };
    let field = selected_row.and_then(|value| value.pointer(&spec.field));
    let matches = match spec.predicate {
        Some(
            PresencePredicate::ConfigCommand
            | PresencePredicate::ConfigCommandAbsent
            | PresencePredicate::ConfigSecret,
        ) => false,
        None => field == Some(&spec.expected),
        Some(PresencePredicate::Absent) => {
            spec.field.rsplit_once('/').is_some_and(|(parent, _)| {
                selected
                    .and_then(|value| value.pointer(parent))
                    .is_some_and(Value::is_object)
            }) && field.is_none()
        }
        Some(PresencePredicate::Contains) => field.and_then(Value::as_array).is_some_and(|rows| {
            rows.iter()
                .any(|row| verification::contains(row, &spec.expected))
        }),
        Some(PresencePredicate::Excludes) => field.and_then(Value::as_array).is_some_and(|rows| {
            !rows
                .iter()
                .any(|row| verification::contains(row, &spec.expected))
        }),
        Some(PresencePredicate::Present) => field.is_some_and(|value| !value.is_null()),
        Some(PresencePredicate::NonEmpty) => field
            .and_then(Value::as_str)
            .is_some_and(|text| !text.is_empty()),
        Some(PresencePredicate::LengthRange { minimum, maximum }) => field
            .and_then(Value::as_str)
            .is_some_and(|text| (minimum..=maximum).contains(&text.len())),
        Some(PresencePredicate::MarkerOrLengthRange { minimum, maximum }) => {
            field == Some(&Value::Bool(true))
                || field
                    .and_then(Value::as_str)
                    .is_some_and(|text| (minimum..=maximum).contains(&text.len()))
        }
    };
    if !matches {
        return Err(WorkflowError::VerificationFailed {
            field: if spec.field.is_empty() {
                spec.path.join("/")
            } else {
                spec.field.clone()
            },
        });
    }
    Ok(())
}

/// Scrubs router-controlled retained error detail before crossing the workflow boundary.
fn scrub_error(secrets: &SecretValue, mut error: RciError) -> RciError {
    scrub_error_mut(secrets, &mut error);
    error
}

/// Mutates only the router-provided text fields of an RCI error.
fn scrub_error_mut(secrets: &SecretValue, error: &mut RciError) {
    if let RciError::Rci {
        pointer: _,
        code,
        ident,
        message,
    } = error
    {
        *code = secrets.scrub_text(code);
        *ident = secrets.scrub_text(ident);
        *message = secrets.scrub_text(message);
    }
}

/// Scrubs both decoded JSON and the independently retained status projections.
fn scrub_response(secrets: &SecretValue, response: &mut RciResponse) {
    secrets.scrub(&mut response.value);
    for (_pointer, status) in response.statuses.iter_mut().chain(&mut response.warnings) {
        status.code = secrets.scrub_text(&status.code);
        status.ident = secrets.scrub_text(&status.ident);
        status.message = secrets.scrub_text(&status.message);
    }
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

/// Names whether a successful raw change remains unsaved or was persisted by the router.
const fn applied_outcome(persists_immediately: bool) -> &'static str {
    if persists_immediately {
        "applied_persisted"
    } else {
        "applied_unsaved"
    }
}
