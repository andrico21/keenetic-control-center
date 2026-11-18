//! Live migration rehearsal: backup, plan, apply, verify, then rollback or commit.

use alloc::sync::Arc;
use core::{error::Error, hash::BuildHasher as _};
use std::{fs, hash::RandomState, path::PathBuf};

use kcc_app::{
    audit::{Actor, ActorKind, AuditLog},
    backups::BackupStore,
    jobs::JobRunner,
    permissions::{Permission, Role},
    persist::StateStore,
    registry::{ManagedRouterProfile, RouterRegistry},
    secrets::MasterKey,
    workflow::ChangeWorkflow,
};
use kcc_migrate::{
    apply::{Applier, ApplyRequest, ApplySource},
    inventory::{InventoryClient, TargetInventory},
    planner::{Choices, MigrationMaps, MigrationPlan, PlanError, Planner},
    source::SourceConfig,
};
use kcc_rci::{ConfigKind, SecretBytes, capabilities::SupportTier};
use secrecy::{ExposeSecret as _, SecretString};
use serde_json::json;
use tempfile::TempDir;
use url::Url;

use super::{evidence::Evidence, guard::Admitted, probe};

/// Where the source configuration comes from.
pub(crate) enum SourceInput {
    /// Saved startup configuration (the default).
    File(PathBuf),
    /// Live source router.
    Live {
        /// Source origin.
        url: String,
        /// Source account.
        login: String,
        /// Source password file.
        password_file: PathBuf,
    },
}

/// One admitted rehearsal.
pub(crate) struct Rehearsal {
    /// Admission result.
    pub admitted: Admitted,
    /// Target origin.
    pub url: String,
    /// Target account.
    pub login: String,
    /// Target password file.
    pub password_file: PathBuf,
    /// Target password, for an unchanged login-user password choice.
    pub password: SecretString,
    /// Migration source.
    pub source: SourceInput,
    /// Commit instead of the default rollback.
    pub commit: bool,
}

/// Runs the rehearsal, writing value-free evidence lines.
///
/// # Errors
/// Returns setup, planning, apply, verification, rollback or commit failures.
// NOT cancel-safe: mutates the admitted test router under fail-safe protection.
pub(crate) async fn run(
    rehearsal: Rehearsal,
    evidence: &mut Evidence,
) -> Result<(), Box<dyn Error>> {
    let services = Services::open(&rehearsal).await?;
    let target_client = services
        .registry
        .bootstrap_client(&services.role, "target")
        .await?;
    let startup = target_client.download_config(ConfigKind::Startup).await?;
    let backup = services.backups.create(
        "target",
        "pre-migration",
        &SecretString::from(String::from_utf8(startup.expose_secret().to_vec())?),
    )?;
    evidence.record(&json!({"event":"backup","created":!backup.name.is_empty()}))?;
    let (bytes, apply_source) = services.source(&rehearsal.source).await?;
    let source = SourceConfig::from_bytes(bytes.expose_secret())?;
    let inventory = TargetInventory::collect(
        &InventoryClient::from_client(&target_client),
        source.firmware,
    )
    .await?;
    let (plan, management_password) = plan(&source, &inventory, &rehearsal, evidence)?;
    let lines = probe::planned_lines(&plan);
    let mut request = ApplyRequest::new(
        Arc::clone(&services.workflow),
        services.audit.clone(),
        Actor::new(ActorKind::Cli, "live-rehearsal".to_owned()),
        services.role.clone(),
        "target".to_owned(),
        plan,
        apply_source,
    );
    request.options.ack_documentation_tier =
        inventory.info.support_tier() == SupportTier::DocumentationBased;
    request.options.management_password = management_password;
    let (_id, done) = Applier::start(&services.runner, request).await?;
    let mut applier = done.await??;
    let report = applier.report().clone();
    for (index, context) in &lines {
        let outcome = if report.applied.contains(index) {
            "applied"
        } else if report.failed.contains(index) {
            "rejected"
        } else {
            "not-attempted"
        };
        evidence.record(
            &json!({"event":"parse","source_index":index,"context":context,"outcome":outcome}),
        )?;
    }
    evidence.record(&json!({
        "event":"apply",
        "failure":report.failure.map(|failure| format!("{failure:?}")),
        "verified":report.verified,
    }))?;
    if rehearsal.commit && report.failure.is_none() {
        applier.commit().await?;
        evidence.record(&json!({"event":"finish","action":"commit"}))?;
    } else {
        applier.rollback().await?;
        evidence.record(&json!({"event":"finish","action":"rollback"}))?;
    }
    drop(applier);
    match probe::realms(&source, inventory.realm.as_deref()) {
        None => evidence.record(&json!({"event":"password-hash","outcome":"realm-unknown"}))?,
        Some(realms) => {
            let target = probe::Probe {
                client: &rehearsal.admitted.connection.client,
                url: &rehearsal.url,
                outbound: &rehearsal.admitted.outbound,
            };
            let observed = probe::password_hash(&target, realms).await?;
            evidence.record(&json!({
                "event":"password-hash",
                "cross_model":!realms.source.eq_ignore_ascii_case(realms.target),
                "source_realm_hash_accepted":observed.source_accepted,
                "target_realm_hash_accepted":true,
            }))?;
        }
    }
    if let Some(failure) = report.failure {
        return Err(format!("migration failed: {failure:?}").into());
    }
    if !report.verified {
        return Err("migration was not verified".into());
    }
    Ok(())
}

/// Plans and answers input requests; the login user keeps its current password.
///
/// # Errors
/// Returns planning failures and requests no automatic choice can answer.
fn plan(
    source: &SourceConfig,
    inventory: &TargetInventory,
    rehearsal: &Rehearsal,
    evidence: &mut Evidence,
) -> Result<(MigrationPlan, Option<SecretString>), Box<dyn Error>> {
    let mut choices = Choices::default();
    let mut management_password = None;
    for _round in 0_u8..3 {
        let blocked = match Planner::plan(source, inventory, &MigrationMaps::default(), &choices) {
            Ok(plan) => return Ok((plan, management_password)),
            Err(PlanError::PlanBlocked { items }) => items,
            Err(error) => return Err(error.into()),
        };
        for item in blocked {
            let needed = item.needed_input.unwrap_or_default();
            evidence.record(&json!({"event":"needs-input","rule":item.rule_id}))?;
            if let Some(user) = needed.strip_prefix("new password for ") {
                let password = if user == rehearsal.login {
                    let current = rehearsal.password.clone();
                    management_password = Some(current.clone());
                    current
                } else {
                    SecretString::from(format!("{:016x}", RandomState::new().hash_one(user)))
                };
                drop(choices.new_passwords.insert(user.to_owned(), password));
            } else if needed == "confirm reconnect URL" {
                choices.reconnect_url = Some(rehearsal.url.clone());
            } else {
                return Err(format!("unanswerable input for rule {}", item.rule_id).into());
            }
        }
    }
    Err("plan stayed blocked".into())
}

/// Isolated application services around the admitted target.
struct Services {
    /// Temporary state owner.
    _directory: TempDir,
    /// Registered routers.
    registry: Arc<RouterRegistry>,
    /// Operator role.
    role: Role,
    /// Encrypted backups.
    backups: Arc<BackupStore>,
    /// Audit writer.
    audit: AuditLog,
    /// Protected workflow.
    workflow: Arc<ChangeWorkflow>,
    /// Job runner.
    runner: Arc<JobRunner>,
}

impl Services {
    /// Opens state, registers the target with its profile flags and starts the services.
    ///
    /// # Errors
    /// Returns state, registry, key or job-runner failures.
    // NOT cancel-safe: writes temporary state.
    async fn open(rehearsal: &Rehearsal) -> Result<Self, Box<dyn Error>> {
        let directory = TempDir::new()?;
        let state = StateStore::open(&directory.path().join("state"))?;
        let registry = Arc::new(RouterRegistry::new(
            state.clone(),
            &[],
            &rehearsal.admitted.outbound,
        )?);
        let role = Role::new("admin".to_owned(), Permission::ALL, Vec::new());
        let mut target = ManagedRouterProfile::new(
            "target".to_owned(),
            Url::parse(&rehearsal.url)?,
            rehearsal.login.clone(),
            rehearsal.password_file.clone(),
        );
        target.test_device = rehearsal.admitted.profile.test_device;
        target.tls = rehearsal.admitted.profile.tls.clone();
        registry.create(&role, target).await?;
        let backups = Arc::new(BackupStore::new(state.clone(), MasterKey::generate()?));
        let audit = AuditLog::spawn(&state)?;
        let workflow = ChangeWorkflow::new(
            state.clone(),
            Arc::clone(&registry),
            Arc::clone(&backups),
            audit.clone(),
        );
        let runner = JobRunner::open(state, Arc::clone(&registry), audit.clone()).await?;
        Ok(Self {
            _directory: directory,
            registry,
            role,
            backups,
            audit,
            workflow,
            runner,
        })
    }

    /// Reads the source configuration and builds the matching apply source.
    ///
    /// # Errors
    /// Returns file, registry or transport failures.
    // NOT cancel-safe: registers the live source.
    async fn source(
        &self,
        input: &SourceInput,
    ) -> Result<(SecretBytes, ApplySource), Box<dyn Error>> {
        match input {
            SourceInput::File(path) => {
                let bytes = SecretBytes::from(fs::read(path)?);
                Ok((bytes.clone(), ApplySource::File(bytes)))
            }
            SourceInput::Live {
                url,
                login,
                password_file,
            } => {
                let profile = ManagedRouterProfile::new(
                    "source".to_owned(),
                    Url::parse(url)?,
                    login.clone(),
                    password_file.clone(),
                );
                self.registry.create(&self.role, profile).await?;
                let client = self.registry.client("source").await?;
                let bytes = client.download_config(ConfigKind::Startup).await?;
                Ok((
                    bytes,
                    ApplySource::LiveRouter {
                        id: "source".to_owned(),
                        client,
                    },
                ))
            }
        }
    }
}
