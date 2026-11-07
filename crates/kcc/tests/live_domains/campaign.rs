//! The campaign: gate, reads of every domain, then reversible writes under the safety net.

use alloc::sync::Arc;
use core::error::Error;
use std::path::PathBuf;

use kcc_app::{
    audit::{Actor, ActorKind, AuditLog},
    backups::BackupStore,
    permissions::{Permission, Role},
    persist::StateStore,
    registry::{ManagedRouterProfile, RouterRegistry},
    secrets::MasterKey,
    workflow::ChangeWorkflow,
};
use kcc_catalog::Catalog;
use kcc_domain::{DomainId, RouterCtx, registry};
use kcc_rci::capabilities::RouterInfo;
use kcc_testkit::live_matrix::Run;
use secrecy::SecretString;
use tempfile::TempDir;
use url::Url;

use super::{
    gate::{self, WriteAdmission},
    reads::{self, ReadOutcome},
    safety,
    writes::{self, WriteOutcome, Writer},
};

/// Whether the campaign may write.
pub(crate) enum WriteMode {
    /// Reads only; the router receives no write.
    ReadOnly,
    /// Writes requested; admitted only by a `test_device = true` profile in this config.
    Requested(PathBuf),
}

/// Inputs shared by the live run and the hermetic twin.
pub(crate) struct Options {
    /// Router origin.
    pub url: String,
    /// Router account.
    pub login: String,
    /// Router password.
    pub password: SecretString,
    /// Password file, for the workflow registry.
    pub password_file: PathBuf,
    /// Allowed serials.
    pub allowed: Vec<String>,
    /// Write gate.
    pub write: WriteMode,
    /// Permits loopback routers (hermetic tests only).
    pub allow_loopback: bool,
    /// Leaves this domain's write applied (the safety-net mutation check only).
    pub leave_unreverted: Option<DomainId>,
}

/// What the campaign did.
pub(crate) struct Report {
    /// Matrix identity of the router.
    pub run: Run,
    /// Every read.
    pub reads: Vec<ReadOutcome>,
    /// Every domain's write outcome; empty in read-only mode.
    pub writes: Vec<WriteOutcome>,
}

impl Report {
    /// Logs value-free per-operation lines.
    pub(crate) fn log(&self) {
        for read in &self.reads {
            tracing::info!(domain = ?read.domain, command = read.command, result = ?read.result, "read");
        }
        for write in &self.writes {
            tracing::info!(domain = ?write.domain, result = ?write.result, "write");
        }
    }
}

/// Runs the campaign against one router.
///
/// # Errors
/// Returns refusals, read or write failures, and a running-config snapshot mismatch.
// NOT cancel-safe: an admitted run mutates the test router under the fail-safe timer.
pub(crate) async fn run(options: Options) -> Result<Report, Box<dyn Error>> {
    let opened = gate::open(&options).await?;
    let info = RouterInfo::detect(&opened.connection.session, &opened.connection.router).await?;
    let run = Run::observed(&opened.serial, &info);
    let ctx = RouterCtx::new(
        Arc::new(opened.connection.client),
        Catalog::for_router(&info)?,
    );
    let reads = reads::read_all(&ctx).await?;
    let Some(admission) = opened.write else {
        return Ok(Report {
            run,
            reads,
            writes: Vec::new(),
        });
    };
    let workflow = Workflow::open(&options, &admission).await?;
    let before = safety::snapshot(&ctx.client).await?;
    drop(ctx.client.parse(safety::ARM).await?);
    let mut changes = workflow
        .service
        .begin(
            "target",
            Actor::new(ActorKind::Cli, "live-domains".to_owned()),
            &admin(),
            None,
            false,
        )
        .await?;
    let mut writes = Vec::new();
    for domain in registry() {
        let mut probe = Writer {
            changes: &mut changes,
            ctx: &ctx,
            running: &before,
            revert: options.leave_unreverted != Some(domain.id),
        };
        writes.push(WriteOutcome {
            domain: domain.id,
            result: writes::exercise(&mut probe, domain.id).await?,
        });
    }
    drop(changes);
    safety::compare(&ctx.client, &before).await?;
    drop(ctx.client.parse(safety::DISARM).await?);
    drop(workflow);
    Ok(Report { run, reads, writes })
}

/// Administrator role of the campaign's change sets.
fn admin() -> Role {
    Role::new("admin".to_owned(), Permission::ALL, Vec::new())
}

/// The protected workflow around the admitted router, on temporary state.
struct Workflow {
    /// Temporary state owner.
    _directory: TempDir,
    /// Workflow service.
    service: Arc<ChangeWorkflow>,
}

impl Workflow {
    /// Registers the router with its profile flags and opens the workflow services.
    ///
    /// # Errors
    /// Returns state, registry or key failures.
    // NOT cancel-safe: writes temporary state.
    async fn open(options: &Options, admission: &WriteAdmission) -> Result<Self, Box<dyn Error>> {
        let directory = TempDir::new()?;
        let state = StateStore::open(&directory.path().join("state"))?;
        let registry = Arc::new(RouterRegistry::new(
            state.clone(),
            &[],
            &admission.outbound,
        )?);
        let mut profile = ManagedRouterProfile::new(
            "target".to_owned(),
            Url::parse(&options.url)?,
            options.login.clone(),
            options.password_file.clone(),
        );
        profile.test_device = admission.profile.test_device;
        profile.tls = admission.profile.tls.clone();
        registry.create(&admin(), profile).await?;
        let backups = Arc::new(BackupStore::new(state.clone(), MasterKey::generate()?));
        let audit = AuditLog::spawn(&state)?;
        Ok(Self {
            _directory: directory,
            service: ChangeWorkflow::new(state, registry, backups, audit),
        })
    }
}
