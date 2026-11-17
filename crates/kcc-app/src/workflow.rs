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
use std::{
    sync::{Mutex as SyncMutex, PoisonError},
    time::SystemTime,
};

use kcc_catalog::{Catalog, HttpMethod, Risk, SecretValue, ValidatedRequest, ValidationIssue};
use kcc_rci::{
    ConfigKind, RciBody, RciClient, RciError, RciPath, RciResponse, RouterUrl, SecretBytes,
    auth::Credentials, capabilities::SystemMode, engine::batch::BatchError,
};
use secrecy::{ExposeSecret as _, SecretString};
use serde::Serialize;
use serde_json::{Value, json};

#[path = "workflow_batch.rs"]
mod batch;
#[path = "workflow_cli.rs"]
mod cli;
#[path = "workflow_credential.rs"]
mod credential;
#[path = "workflow_output.rs"]
mod output;
#[path = "workflow_receipts.rs"]
mod receipts;
#[path = "workflow_recovery.rs"]
mod recovery;
#[path = "workflow_refusal.rs"]
pub mod refusal;
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

use self::{credential::Baseline, receipts::Receipts, recovery::Refresh};
use crate::{
    accounts::{Clock as _, SystemClock},
    audit::{
        Actor, AuditError, AuditEvent, AuditLog,
        receipt::{AuditReceipt, Pending},
        request_id,
    },
    backups::{BackupError, BackupStore},
    brackets::{BracketGuard, Brackets},
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
    /// A named configuration credential has a bounded nonempty protected payload that
    /// differs from the one stored before the write, when one was stored.
    ConfigSecretReplaced,
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

    /// Expects the running-configuration credential stored under the command words
    /// `prefix` (such as `user admin password`) to differ from the one stored before the
    /// write; a failure names `prefix`, never the credential.
    #[inline]
    #[must_use]
    pub fn replaced(prefix: String) -> Self {
        Self {
            row: None,
            path: Vec::new(),
            expected: Value::String(prefix.clone()),
            field: prefix,
            predicate: Some(PresencePredicate::ConfigSecretReplaced),
        }
    }
}

/// How a [`ChangeRequest`] reaches its RCI resource.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub enum ChangeMethod {
    /// Sets the resource from the request body.
    Post,
    /// Deletes the resource; the body becomes the query parameters.
    Delete,
}

/// One validated mutation or deletion request.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[non_exhaustive]
pub struct ChangeRequest {
    /// Whether the body is posted or the resource deleted.
    pub method: ChangeMethod,
    /// Space-separated catalog path.
    pub catalog_path: String,
    /// Slash-separated RCI resource path segments.
    pub rci_path: Vec<String>,
    /// Mutation body, or the deletion query parameters.
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
            method: ChangeMethod::Post,
            catalog_path,
            rci_path,
            body: protected_body,
            verify,
            permission,
            audit_params,
        }
    }

    /// Creates a deletion request whose `query` parameters are protected like a body.
    #[inline]
    #[must_use]
    pub fn delete(
        catalog_path: String,
        rci_path: Vec<String>,
        query: Value,
        verify: Vec<VerificationSpec>,
        permission: Permission,
        audit_params: Value,
    ) -> Self {
        let request = Self::new(
            catalog_path,
            rci_path,
            query,
            verify,
            permission,
            audit_params,
        );
        Self {
            method: ChangeMethod::Delete,
            ..request
        }
    }
}

/// One root RCI batch item; the workflow validates it from its value.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[non_exhaustive]
pub struct BatchItem {
    /// Root RCI object sent to the router.
    pub value: SecretValue,
}

impl BatchItem {
    /// Protects one root RCI object.
    #[inline]
    #[must_use]
    pub fn new(value: Value) -> Self {
        Self {
            value: SecretValue::new("", value),
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
    /// Successful change items containing management operations.
    pub applied_management_changes: usize,
    /// Successful ordinary writes remain unsaved until an explicit save.
    pub unsaved: bool,
    /// The batch's audit entry: written, or still queued.
    pub audit: AuditReceipt,
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
    /// The commands may end the router session (reboot, reset): the workflow neither reads
    /// back nor reads the router's state afterwards, and audits the outcome as unknown.
    pub terminal: bool,
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
            terminal: false,
        }
    }

    /// Creates a protected terminal CLI parser mutation, which needs no reachable router
    /// once its commands are sent.
    #[inline]
    #[must_use]
    pub fn terminal(
        commands: Vec<CliCommand>,
        permission: Permission,
        audit_params: Value,
    ) -> Self {
        let request = Self::new(commands, Vec::new(), permission, audit_params);
        Self {
            terminal: true,
            ..request
        }
    }
}

/// Successful CLI parser mutation result.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct CliChangeResult {
    /// Ordinary writes always remain unsaved until an explicit save.
    pub unsaved: bool,
    /// Ordered router responses for the parser commands.
    pub responses: Vec<RciBody>,
    /// The change's audit entry: written, or still queued.
    pub audit: AuditReceipt,
}

/// Successful terminal CLI parser mutation result.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct TerminalCliChangeResult {
    /// Ordered router responses received before the session became unreachable.
    pub responses: Vec<RciBody>,
    /// The change's audit entry: written, or still queued.
    pub audit: AuditReceipt,
}

impl From<CliChangeResult> for TerminalCliChangeResult {
    #[inline]
    fn from(result: CliChangeResult) -> Self {
        Self {
            responses: result.responses,
            audit: result.audit,
        }
    }
}

/// Successful mutation result.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ChangeResult {
    /// Ordinary writes always remain unsaved until an explicit save.
    pub unsaved: bool,
    /// The change's audit entry: written, or still queued.
    pub audit: AuditReceipt,
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
    /// The router's firmware has no command catalog.
    #[error("router firmware has no command catalog")]
    UnsupportedFirmware,
    /// A configuration downloaded from the router could not be decoded.
    #[error("router configuration could not be decoded")]
    UndecodableConfig,
    /// The router answered with a body of an unexpected kind or shape.
    #[error("router returned an unexpected response body")]
    UnexpectedBody,
    /// The planning layer refused the change.
    #[error(transparent)]
    Refused(#[from] refusal::Refusal),
    /// Explicit save or commit did not settle before the deadline.
    #[error("router save timed out")]
    SaveTimeout,
    /// The router's recovery timer is already armed by somebody else; a safety bracket
    /// leaves it to its owner and sends nothing.
    #[error("the router's recovery timer is already armed")]
    RecoveryTimerInUse,
    /// The request that would make the change no longer has an owner; nothing was sent.
    #[error("the change has no owner any more")]
    Unowned,
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
    /// In-process actor labels for better busy errors (held synchronously, never across await).
    lease_actors: SyncMutex<BTreeMap<String, String>>,
    /// The process's open safety brackets.
    brackets: Brackets,
}

impl fmt::Debug for ChangeWorkflow {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ChangeWorkflow")
            .field("state", &self.state)
            .field("registry", &self.registry)
            .field("backups", &self.backups)
            .field("audit", &self.audit)
            .field("brackets", &self.brackets)
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
            lease_actors: SyncMutex::new(BTreeMap::new()),
            brackets: Brackets::default(),
        })
    }

    /// Starts a leased change set after checking permission and scope; the router state
    /// it reads becomes the baseline that later writes are checked against.
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
        force: bool,
    ) -> Result<ChangeSet, WorkflowError> {
        let reservation = self.reserve(router, &actor, role)?;
        self.begin_with_client(reservation, actor, role, force, None)
            .await
    }

    /// Takes `router`'s write lease for `actor` before its change set begins, so that a
    /// busy router is refused before any work is started for it; dropping the
    /// reservation releases the lease.
    ///
    /// # Errors
    ///
    /// Returns busy, permission, audit, or state errors.
    pub fn reserve(
        self: &Arc<Self>,
        router: &str,
        actor: &Actor,
        role: &Role,
    ) -> Result<Reservation, WorkflowError> {
        self.audit_alive()?;
        authorize(role, Permission::Read, router).map_err(map_permission)?;
        let lease = match self.state.try_lease(router) {
            Ok(lease) => lease,
            Err(StateError::StateLocked { path: _ }) => {
                let actor_name = self
                    .lease_actors
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
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
                .unwrap_or_else(PoisonError::into_inner)
                .insert(router.to_owned(), actor.id.clone()),
        );
        Ok(Reservation {
            router: router.to_owned(),
            actor_label: LeaseActorGuard {
                workflow: Arc::clone(self),
                router: router.to_owned(),
            },
            lease,
        })
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
        let reservation = self.reserve(router, &actor, role)?;
        self.begin_with_client(reservation, actor, role, false, Some(client))
            .await
    }

    /// Starts a migration change set on the lease `reservation` already holds.
    ///
    /// # Errors
    /// Returns authentication, inventory, or last-change failures.
    // NOT cancel-safe: cancellation releases the reserved lease.
    pub async fn begin_reserved_migration(
        self: &Arc<Self>,
        reservation: Reservation,
        actor: Actor,
        role: &Role,
    ) -> Result<ChangeSet, WorkflowError> {
        let client = self
            .registry
            .bootstrap_client(role, &reservation.router)
            .await?;
        self.begin_with_client(reservation, actor, role, false, Some(client))
            .await
    }

    /// Begins a change set on a reserved lease using a caller-selected migration client
    /// when supplied.
    // NOT cancel-safe: cancellation releases the reserved lease.
    async fn begin_with_client(
        self: &Arc<Self>,
        reservation: Reservation,
        actor: Actor,
        role: &Role,
        force: bool,
        selected: Option<Arc<RciClient>>,
    ) -> Result<ChangeSet, WorkflowError> {
        let Reservation {
            router,
            actor_label,
            lease,
        } = reservation;
        let migration = selected.is_some();
        let client = match selected {
            Some(client) => client,
            None => self.registry.client(&router).await?,
        };
        let baseline = read_last_change(&client).await?;
        let info = if migration {
            client.detect().await?
        } else {
            self.registry.poll_info(&router).await?
        };
        let catalog =
            Catalog::for_router(&info).map_err(|_error| WorkflowError::UnsupportedFirmware)?;
        Ok(ChangeSet {
            workflow: Arc::clone(self),
            router,
            actor,
            role: role.clone(),
            client,
            catalog,
            baseline: baseline.clone(),
            expected: baseline,
            system_mode: info.system_mode,
            backed_up: false,
            force,
            lease: Some(lease),
            actor_label: Some(actor_label),
            receipts: Receipts::default(),
            request_id: request_id::next("change"),
        })
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

    /// Refuses work that cannot produce its required audit receipt.
    ///
    /// # Errors
    /// Returns a typed audit failure after the writer terminates.
    pub fn audit_alive(&self) -> Result<(), WorkflowError> {
        self.audit.require_alive().map_err(Into::into)
    }

    /// The safety brackets open in this process, for a server that waits for them before it
    /// exits.
    #[inline]
    #[must_use]
    pub const fn brackets(&self) -> &Brackets {
        &self.brackets
    }
}

/// A router's write lease taken before the change set that uses it; dropping it releases
/// the lease.
#[non_exhaustive]
pub struct Reservation {
    /// Router id.
    router: String,
    /// Removes the actor label before the lease is released (fields drop in order).
    actor_label: LeaseActorGuard,
    /// Cross-process lease.
    lease: StateLock,
}

impl fmt::Debug for Reservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Reservation")
            .field("router", &self.router)
            .finish_non_exhaustive()
    }
}

/// Guard that removes the actor label from `lease_actors` on drop.
struct LeaseActorGuard {
    /// Shared workflow reference.
    workflow: Arc<ChangeWorkflow>,
    /// Router id to remove from the lease map.
    router: String,
}

impl Drop for LeaseActorGuard {
    fn drop(&mut self) {
        drop(
            self.workflow
                .lease_actors
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .remove(&self.router),
        );
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
    /// System mode detected when the set began; `None` when the router does not report one.
    system_mode: Option<SystemMode>,
    /// Whether this set made its required backup.
    backed_up: bool,
    /// Whether optimistic conflicts are explicitly overridden.
    force: bool,
    /// Cross-process lease.
    lease: Option<StateLock>,
    /// Guard that removes the actor label from `lease_actors` on drop.
    actor_label: Option<LeaseActorGuard>,
    /// Audit entries still queued when their change returned.
    receipts: Receipts,
    /// Correlation id of every audit entry of this set.
    request_id: String,
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
            .field("request_id", &self.request_id)
            .finish_non_exhaustive()
    }
}

impl Drop for ChangeSet {
    fn drop(&mut self) {
        drop(self.actor_label.take());
        drop(self.lease.take());
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
        let password = self
            .workflow
            .registry
            .get(&self.router)?
            .profile
            .password_file
            .is_some();
        let credentials = original.credentials();
        self.workflow
            .registry
            .transition(
                &self.router,
                Arc::clone(&original),
                password.then_some(credentials),
            )
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
            .transition(&self.router, Arc::clone(&client), credentials)
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
        self.prepare(Permission::Destructive).await?;
        drop(self.client.upload_startup_config(bytes).await?);
        drop(
            self.audit_cli(
                &[],
                "router.raw_restore_upload",
                json!({}),
                "startup_replaced",
            )
            .await?,
        );
        Ok(())
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

    /// Applies one mutation or deletion after catalog validation, backup, conflict check,
    /// and read-back.
    ///
    /// # Errors
    ///
    /// Returns validation, conflict, backup, request, verification, or audit errors.
    // NOT cancel-safe: cancellation after transmission may leave an applied unaudited mutation.
    pub async fn apply(&mut self, request: ChangeRequest) -> Result<ChangeResult, WorkflowError> {
        authorize(&self.role, request.permission, &self.router).map_err(map_permission)?;
        let wire = request.body.expose_for_send();
        let http_method = match request.method {
            ChangeMethod::Post => HttpMethod::Post,
            ChangeMethod::Delete => HttpMethod::Delete,
        };
        let validated = self
            .catalog
            .validate(&request.catalog_path, http_method, wire.expose_secret())
            .map_err(|issues| WorkflowError::CatalogValidation { issues })?;
        if request.method == ChangeMethod::Delete && validated.has_secrets() {
            return Err(RciError::Validation.into());
        }
        self.check_conflict().await?;
        self.ensure_backup().await?;
        let baseline = Baseline::capture(&self.client, &request.verify).await?;
        let path =
            RciPath::from_segments(&request.rci_path).map_err(|_error| RciError::Validation)?;
        let sent = match request.method {
            ChangeMethod::Post => self.client.post(&path, wire.expose_secret()).await,
            ChangeMethod::Delete => self.client.delete(&path, wire.expose_secret()).await,
        };
        drop(sent.map_err(|error| scrub_error(validated.protected_value(), error))?);
        for verification in &request.verify {
            verification::verify(&self.client, verification, &baseline).await?;
        }
        self.expected = read_last_change(&self.client).await?;
        let (action, outcome, unsaved) = match request.method {
            ChangeMethod::Post if validated.risk == Risk::Read => (
                "router.change",
                "success",
                !validated.ordinary_paths.is_empty(),
            ),
            ChangeMethod::Post => (
                "router.change",
                applied_outcome(validated.persists_immediately),
                !validated.ordinary_paths.is_empty(),
            ),
            ChangeMethod::Delete => (
                "router.change_delete",
                applied_outcome(validated.persists_immediately),
                true,
            ),
        };
        let timestamp = SystemClock.unix_seconds();
        let mut audit_params = request.audit_params;
        validated.protected_value().scrub(&mut audit_params);
        let event = AuditEvent::new(timestamp, self.actor.clone(), action.to_owned())
            .with_router(self.router.clone())
            .with_target(request.catalog_path)
            .with_params(audit_params)
            .with_result(outcome.to_owned(), self.request_id.clone());
        let audit = self.receipts.record(&self.workflow.audit, event).await?;
        Ok(ChangeResult { unsaved, audit })
    }

    /// Applies root RCI items under the normal write protections, each validated once from
    /// the value it sends.
    ///
    /// # Errors
    ///
    /// Returns permission, validation, conflict, backup, request, verification, or audit
    /// errors.
    // NOT cancel-safe: cancellation after transmission may leave applied unaudited mutations.
    pub async fn apply_batch(
        &mut self,
        request: BatchChangeRequest,
    ) -> Result<BatchChangeResult, WorkflowError> {
        authorize(&self.role, request.permission, &self.router).map_err(map_permission)?;
        let wire = request
            .items
            .iter()
            .map(|item| item.value.expose_for_send())
            .collect::<Vec<_>>();
        let validated = wire
            .iter()
            .map(|value| {
                self.catalog
                    .validate("", HttpMethod::Post, value.expose_secret())
                    .map_err(|issues| WorkflowError::CatalogValidation { issues })
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.check_conflict().await?;
        self.ensure_backup().await?;
        let baseline = Baseline::capture(&self.client, &request.verify).await?;
        let values = wire
            .iter()
            .map(|value| value.expose_secret().clone())
            .collect();
        let mut responses = match self.client.batch(values).await {
            Ok(responses) => responses,
            Err(failure) => {
                return Err(self.interrupted_batch(&request, &validated, failure).await);
            }
        };
        for response in &mut responses {
            for item in &request.items {
                match response {
                    Ok(value) => scrub_response(&item.value, value),
                    Err(error) => scrub_error_mut(&item.value, error),
                }
            }
        }
        for verification in &request.verify {
            verification::verify(&self.client, verification, &baseline).await?;
        }
        self.expected = read_last_change(&self.client).await?;
        let timestamp = SystemClock.unix_seconds();
        let completion =
            batch::completion(validated.iter().zip(responses.iter().map(Result::is_ok)));
        let outcome = completion.outcome();
        let audit_params = if completion.failed == 0 {
            request.audit_params
        } else {
            completion.refusal_params()
        };
        let event = AuditEvent::new(
            timestamp,
            self.actor.clone(),
            "router.change_batch".to_owned(),
        )
        .with_router(self.router.clone())
        .with_target(batch::target(&validated))
        .with_params(audit_params)
        .with_result(outcome.to_owned(), self.request_id.clone());
        let audit = self.receipts.record(&self.workflow.audit, event).await?;
        Ok(BatchChangeResult {
            applied_changes: completion.applied_changes,
            applied_management_changes: completion.applied_management_changes,
            unsaved: completion.unsaved,
            audit,
            persists_immediately: completion.persists_immediately,
            persisted_paths: completion.persisted_paths,
            responses,
        })
    }

    /// Audits the chunks of a batch the router applied before a later chunk failed, and
    /// returns the scrubbed failure (or the audit failure, which wins).
    // NOT cancel-safe: the writer can append after cancellation.
    async fn interrupted_batch(
        &mut self,
        request: &BatchChangeRequest,
        validated: &[ValidatedRequest],
        failure: BatchError,
    ) -> WorkflowError {
        let BatchError {
            completed,
            mut error,
            ..
        } = failure;
        for item in &request.items {
            error = scrub_error(&item.value, error);
        }
        let Some((params, outcome)) = batch::interrupted(validated, &completed) else {
            return WorkflowError::Rci(error);
        };
        let event = AuditEvent::new(
            SystemClock.unix_seconds(),
            self.actor.clone(),
            "router.change_batch".to_owned(),
        )
        .with_router(self.router.clone())
        .with_target(batch::target(validated))
        .with_params(params)
        .with_result(outcome.to_owned(), self.request_id.clone());
        match self.receipts.record(&self.workflow.audit, event).await {
            Ok(_receipt) => WorkflowError::Rci(error),
            Err(audit) => WorkflowError::from(audit),
        }
    }

    /// Applies catalog-validated CLI parser commands under the normal write protections;
    /// a terminal request skips the read-back and the final state read.
    ///
    /// # Errors
    ///
    /// Returns permission, conflict, backup, request, verification, or audit errors. A
    /// line the router refuses is the error; when it accepted other lines first, their
    /// partial change is audited like a partly refused root batch.
    // NOT cancel-safe: cancellation after transmission may leave applied unaudited mutations.
    pub async fn apply_cli(
        &mut self,
        request: CliChangeRequest,
    ) -> Result<CliChangeResult, WorkflowError> {
        for command in &request.commands {
            drop(command.expose_for_send()?);
        }
        self.prepare(request.permission).await?;
        self.send_cli(request, Refresh::Required).await
    }

    /// Sends a recovery-timer step (disarm, keep-alive, rollback) under the change's
    /// permission and router scope, but without the conflict check and the backup of a
    /// configuration change: a foreign change or a failed backup must never keep the timer
    /// from being stopped or resolved. A foreign change seen before the step stays a
    /// conflict for later writes.
    ///
    /// # Errors
    ///
    /// Returns a local refusal for anything but a recovery-timer request, or permission,
    /// request, verification, or audit errors.
    // NOT cancel-safe: cancellation after transmission may leave the step applied unaudited.
    pub async fn apply_recovery(
        &mut self,
        request: CliChangeRequest,
    ) -> Result<CliChangeResult, WorkflowError> {
        recovery::run(self, request).await
    }

    /// Sends validated, authorized CLI commands, reads back, refreshes the expected state
    /// as `refresh` says, and audits the change.
    // NOT cancel-safe: cancellation after transmission may leave applied unaudited mutations.
    async fn send_cli(
        &mut self,
        request: CliChangeRequest,
        refresh: Refresh,
    ) -> Result<CliChangeResult, WorkflowError> {
        let baseline = if request.terminal {
            Baseline::default()
        } else {
            Baseline::capture(&self.client, &request.verify).await?
        };
        let answers = self.dispatch_cli(&request.commands).await?;
        let completion = batch::completion(
            request
                .commands
                .iter()
                .map(CliCommand::validated)
                .zip(answers.iter().map(Result::is_ok)),
        );
        let responses = match answers.into_iter().collect::<Result<Vec<_>, _>>() {
            Ok(responses) => responses,
            Err(refusal) => {
                if completion.succeeded != 0 {
                    let action = if request.terminal {
                        "router.change_cli_terminal"
                    } else {
                        "router.change_cli"
                    };
                    let (params, outcome) = (completion.refusal_params(), completion.outcome());
                    drop(
                        self.audit_cli(&request.commands, action, params, outcome)
                            .await?,
                    );
                }
                return Err(refusal);
            }
        };
        let unsaved = request
            .commands
            .iter()
            .any(|command| !command.validated().ordinary_paths.is_empty());
        let persists_immediately = !unsaved
            && request
                .commands
                .iter()
                .any(|command| !command.validated().persisted_paths.is_empty());
        let (action, outcome) = if request.terminal {
            ("router.change_cli_terminal", "applied_state_unknown")
        } else {
            for verification in &request.verify {
                verification::verify(&self.client, verification, &baseline).await?;
            }
            match refresh {
                Refresh::Required => self.expected = read_last_change(&self.client).await?,
                Refresh::Optional => {
                    if let Ok(current) = read_last_change(&self.client).await {
                        self.expected = current;
                    }
                }
                Refresh::Keep => {}
            }
            (
                "router.change_cli",
                if !unsaved && !persists_immediately {
                    "success"
                } else {
                    applied_outcome(persists_immediately)
                },
            )
        };
        let audit = self
            .audit_cli(&request.commands, action, request.audit_params, outcome)
            .await?;
        Ok(CliChangeResult {
            unsaved,
            responses,
            audit,
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

    /// Refuses work that cannot produce its required audit receipt.
    ///
    /// # Errors
    /// Returns a typed audit failure after the writer terminates.
    #[inline]
    pub fn audit_alive(&self) -> Result<(), WorkflowError> {
        self.workflow.audit_alive()
    }

    /// Records the set's audit entries under the caller's correlation `request_id` instead
    /// of the one the set drew when it began; the caller keeps it unique per request.
    #[inline]
    #[must_use]
    pub fn with_request_id(mut self, request_id: String) -> Self {
        self.request_id = request_id;
        self
    }

    /// Makes later changes of this set return without waiting for their audit entries,
    /// until [`Self::settle_audit`]; the entries are still written in the order sent.
    #[inline]
    pub const fn defer_audit(&mut self) {
        self.receipts.defer();
    }

    /// Stops deferring and waits at most `limit` for the entries still queued.
    ///
    /// # Errors
    /// Returns the writer's failure when it stopped before writing one of them; entries
    /// still queued at the deadline stay queued and are no error.
    // cancel-safe: waiting only observes the audit writer's progress.
    pub async fn settle_audit(&mut self, limit: Duration) -> Result<(), WorkflowError> {
        Ok(self.receipts.settle(limit).await?)
    }

    /// Whether an audit entry of this set is still queued, to be written once the append
    /// lock is free.
    #[inline]
    #[must_use]
    pub fn audit_pending(&self) -> bool {
        self.receipts.any_pending()
    }

    /// The handles of this set's audit entries that were still queued when their change
    /// returned; each tells later whether its entry was written meanwhile.
    #[inline]
    #[must_use]
    pub fn queued_audit(&self) -> Vec<Pending> {
        self.receipts.queued()
    }

    /// Counts a safety bracket of this change set as open until the guard is dropped.
    #[inline]
    pub fn enter_bracket(&self) -> BracketGuard {
        self.workflow.brackets.enter()
    }

    /// Returns the baseline state captured when this change set began.
    #[inline]
    #[must_use]
    pub const fn baseline(&self) -> &LastChange {
        &self.baseline
    }

    /// Returns the system mode detected when this change set began.
    #[inline]
    #[must_use]
    pub const fn system_mode(&self) -> Option<&SystemMode> {
        self.system_mode.as_ref()
    }

    /// Whether the router's running configuration differed from its startup configuration
    /// when this change set last read it: at its start and after each of its changes.
    #[inline]
    #[must_use]
    pub const fn unsaved(&self) -> bool {
        self.expected.unsaved
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

    /// Runs a write's preflight without sending a change: authorization of `permission`
    /// and the router scope, the conflict check, and the automatic backup. A caller that
    /// must know whether a refused step sent anything runs it first.
    ///
    /// # Errors
    ///
    /// Returns permission, conflict, router request, backup, or state errors.
    // NOT cancel-safe: cancellation can interrupt backup preparation.
    pub async fn prepare(&mut self, permission: Permission) -> Result<(), WorkflowError> {
        authorize(&self.role, permission, &self.router).map_err(map_permission)?;
        self.check_conflict().await?;
        self.ensure_backup().await
    }

    /// Sends CLI commands and returns each line's answer in order; a failed request is the
    /// error.
    // NOT cancel-safe: dispatched commands may apply before cancellation.
    async fn dispatch_cli(
        &self,
        commands: &[CliCommand],
    ) -> Result<Vec<Result<RciBody, WorkflowError>>, WorkflowError> {
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
        let mut answers = match lines.as_slice() {
            [] => Vec::new(),
            [line] => vec![Ok(self.client.parse(line).await.map_err(scrub_failure)?)],
            many => {
                // A failed chunk becomes the answer of its first line, after the lines the
                // router already answered, so a partial change is audited like a refusal.
                let (answered, failure) = match self
                    .client
                    .parse_batch(many.iter().map(|line| line.as_str()))
                    .await
                {
                    Ok(answered) => (answered, None),
                    Err(BatchError {
                        completed, error, ..
                    }) => (completed, Some(error)),
                };
                answered
                    .into_iter()
                    .map(|response| response.map(RciBody::Json).map_err(scrub_failure))
                    .chain(failure.map(|error| Err(scrub_failure(error))))
                    .collect()
            }
        };
        for response in answers.iter_mut().filter_map(|answer| answer.as_mut().ok()) {
            for command in commands {
                match response {
                    RciBody::Json(value) => scrub_response(command.secrets(), value),
                    RciBody::Text(text) => *text = command.secrets().scrub_text(text),
                    _ => return Err(WorkflowError::UnexpectedBody),
                }
            }
        }
        Ok(answers)
    }

    /// Records a CLI mutation audit event without contacting the router.
    // NOT cancel-safe: the writer can append after cancellation.
    async fn audit_cli(
        &mut self,
        commands: &[CliCommand],
        action: &str,
        mut audit_params: Value,
        outcome: &str,
    ) -> Result<AuditReceipt, WorkflowError> {
        let timestamp = SystemClock.unix_seconds();
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
            .with_result(outcome.to_owned(), self.request_id.clone());
        Ok(self.receipts.record(&self.workflow.audit, event).await?)
    }

    /// Refuses any change since the last state observed after this set's own work, by
    /// any agent: every RCI client, kcc's own included, reports the same agent.
    // cancel-safe: only reads router state.
    async fn check_conflict(&self) -> Result<(), WorkflowError> {
        if self.force {
            return Ok(());
        }
        let current = read_last_change(&self.client).await?;
        if current.checksum != self.expected.checksum {
            return Err(WorkflowError::Conflict {
                agent: current.agent,
            });
        }
        Ok(())
    }

    /// Makes at most one automatic backup per router in the rolling window; the backup is
    /// written on the blocking pool.
    // NOT cancel-safe: cancellation can interrupt backup preparation; dropped while the
    // backup is written, the write still completes but the window is not marked.
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
                .map_err(|_error| WorkflowError::UndecodableConfig)?;
            let secret = SecretString::from(text.to_owned());
            let backups = Arc::clone(&self.workflow.backups);
            let router = self.router.clone();
            drop(
                crate::blocking::run(self.workflow.state.dir(), move || {
                    backups.create(&router, "pre-change", &secret)
                })
                .await
                .map_err(WorkflowError::Backup)?,
            );
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
                let event = AuditEvent::new(
                    SystemClock.unix_seconds(),
                    self.actor.clone(),
                    action.to_owned(),
                )
                .with_router(self.router.clone())
                .with_result("saved".to_owned(), self.request_id.clone());
                drop(self.receipts.record(&self.workflow.audit, event).await?);
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
        return Err(WorkflowError::UnexpectedBody);
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

/// Names whether a successful raw change remains unsaved or was persisted by the router.
const fn applied_outcome(persists_immediately: bool) -> &'static str {
    if persists_immediately {
        "applied_persisted"
    } else {
        "applied_unsaved"
    }
}
