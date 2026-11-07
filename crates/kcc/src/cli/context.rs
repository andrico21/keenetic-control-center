//! One invocation's configuration, principal and application services.

extern crate alloc;

use alloc::sync::Arc;
use core::time::Duration;
use std::{
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use kcc_app::{
    accounts::{AccountStore, SystemClock},
    audit::{AuditEvent, AuditLog},
    backups::{BackupRetention, BackupStore},
    permissions::{Permission, Role, load_roles},
    persist::StateStore,
    registry::RouterRegistry,
    secrets::{MasterKey, master_key_path},
    settings::{Config, default_config_dir},
    workflow::ChangeWorkflow,
};
use kcc_catalog::Catalog;
use kcc_domain::RouterCtx;
use kcc_i18n::keys;
use kcc_rci::capabilities::RouterInfo;
use serde_json::Value;

use super::{
    args::Cli,
    exit::{Exit, Failure, Outcome},
    output::Out,
    principal::Principal,
};

/// Global options shared by every command.
#[derive(Debug, Clone)]
pub(crate) struct Globals {
    /// `--config`.
    config: Option<PathBuf>,
    /// `--router`.
    router: Option<String>,
    /// `--yes`.
    yes: bool,
    /// `--confirm-destructive`.
    confirm_destructive: Option<String>,
    /// `--password-file`.
    password_file: Option<PathBuf>,
}

impl Globals {
    /// Copies the global options out of the parsed command line.
    pub(crate) fn from_cli(cli: &Cli) -> Self {
        Self {
            config: cli.config.clone(),
            router: cli.router.clone(),
            yes: cli.yes,
            confirm_destructive: cli.confirm_destructive.clone(),
            password_file: cli.password_file.clone(),
        }
    }

    /// `--config`.
    pub(crate) fn config(&self) -> Option<&Path> {
        self.config.as_deref()
    }

    /// `--yes`.
    pub(crate) const fn yes(&self) -> bool {
        self.yes
    }

    /// `--confirm-destructive`.
    pub(crate) fn confirm_destructive(&self) -> Option<&str> {
        self.confirm_destructive.as_deref()
    }

    /// `--password-file`.
    pub(crate) fn password_file(&self) -> Option<&Path> {
        self.password_file.as_deref()
    }
}

/// The application services a router command needs.
#[derive(Debug)]
pub(crate) struct Services {
    /// Router profiles and clients.
    registry: Arc<RouterRegistry>,
    /// Audit writer.
    audit: AuditLog,
    /// Encrypted backups.
    backups: Arc<BackupStore>,
    /// Protected change workflow.
    workflow: Arc<ChangeWorkflow>,
}

/// One connected router the principal may act on.
#[derive(Debug)]
pub(crate) struct Target {
    /// Profile id.
    id: String,
    /// The principal's role narrowed to this router.
    role: Role,
    /// Domain context.
    router: RouterCtx,
    /// Detected identity.
    info: RouterInfo,
}

/// One invocation.
#[derive(Debug)]
pub(crate) struct Ctx {
    /// Global options.
    globals: Globals,
    /// Output settings.
    out: Out,
    /// Loaded configuration.
    config: Config,
    /// State directory.
    state: StateStore,
    /// Acting principal.
    principal: Principal,
}

impl Ctx {
    /// Loads the configuration and state and resolves the principal.
    ///
    /// # Errors
    ///
    /// Returns configuration, state or role failures.
    pub(crate) fn open(globals: Globals, out: Out) -> Outcome<Self> {
        let config = load_config(globals.config())?;
        let state = StateStore::open(&config.state.resolved_dir()?)?;
        let roles = load_roles(&state)?;
        let principal = Principal::resolve(&config.cli, &roles)?;
        Ok(Self {
            globals,
            out,
            config,
            state,
            principal,
        })
    }

    /// Global options.
    pub(crate) const fn globals(&self) -> &Globals {
        &self.globals
    }

    /// Output settings.
    pub(crate) const fn out(&self) -> Out {
        self.out
    }

    /// State directory.
    pub(crate) const fn state(&self) -> &StateStore {
        &self.state
    }

    /// Acting principal.
    pub(crate) const fn principal(&self) -> &Principal {
        &self.principal
    }

    /// Opens the router services; contacts no router.
    ///
    /// # Errors
    ///
    /// Returns registry, key or audit failures.
    pub(crate) fn services(&self) -> Outcome<Services> {
        let registry = Arc::new(RouterRegistry::new(
            self.state.clone(),
            &self.config.routers,
            &self.config.outbound,
        )?);
        let audit = AuditLog::spawn(&self.state)?;
        let key = MasterKey::load_or_create(&master_key_path()?)?;
        let backups = Arc::new(BackupStore::new(self.state.clone(), key).with_retention(
            BackupRetention::new(self.config.backups.max_age, self.config.backups.keep_last),
        ));
        let workflow = ChangeWorkflow::new(
            self.state.clone(),
            Arc::clone(&registry),
            Arc::clone(&backups),
            audit.clone(),
        );
        Ok(Services {
            registry,
            audit,
            backups,
            workflow,
        })
    }

    /// Opens the Web UI account store.
    ///
    /// # Errors
    ///
    /// Returns key failures.
    pub(crate) fn accounts(&self) -> Outcome<AccountStore> {
        let key = MasterKey::load_or_create(&master_key_path()?)?;
        Ok(AccountStore::new(
            self.state.clone(),
            key,
            self.config.web.lockout,
            Arc::new(SystemClock::default()),
        ))
    }

    /// The router id: `--router`, else the only registered router.
    ///
    /// # Errors
    ///
    /// Returns a usage failure when no router or several routers are registered.
    pub(crate) fn router_id(&self, services: &Services) -> Outcome<String> {
        if let Some(router) = &self.globals.router {
            return Ok(router.clone());
        }
        let entries = services.registry.list()?;
        match entries.as_slice() {
            [only] => Ok(only.profile.id.clone()),
            _ => Err(Failure::message(
                Exit::Usage,
                keys::CLI_ROUTER_REQUIRED,
                &[],
            )),
        }
    }

    /// Authorizes `permissions` on the selected router, then connects to it.
    ///
    /// Refusals are audited and happen before any router request.
    ///
    /// # Errors
    ///
    /// Returns the policy refusal, or connection and detection failures.
    // cancel-safe: connecting and detection only read router state.
    pub(crate) async fn target(
        &self,
        services: &Services,
        permissions: &[Permission],
    ) -> Outcome<Target> {
        let id = self.router_id(services)?;
        let role = match self.principal.authorize(permissions, &[id.as_str()]) {
            Ok(role) => role,
            Err(failure) => {
                self.audit(services, "cli.refused", Some(&id), Value::Null, "forbidden")
                    .await;
                return Err(failure);
            }
        };
        drop(services.registry.get(&id)?);
        let client = services.registry.client(&id).await?;
        let info = services.registry.poll_info(&id).await?;
        let catalog =
            Catalog::for_router(&info).map_err(|error| Failure::text(Exit::Router, &error))?;
        Ok(Target {
            id,
            role,
            router: RouterCtx::new(client, catalog),
            info,
        })
    }

    /// Appends one CLI audit entry; a failing audit write is reported but does not hide
    /// the command's own result.
    // NOT cancel-safe: the writer may append after cancellation.
    pub(crate) async fn audit(
        &self,
        services: &Services,
        action: &str,
        router: Option<&str>,
        params: Value,
        outcome: &str,
    ) {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs());
        let mut event = AuditEvent::new(timestamp, self.principal.actor(), action.to_owned())
            .with_params(params)
            .with_result(outcome.to_owned(), format!("cli-{timestamp}"));
        if let Some(name) = router {
            event = event.with_router(name.to_owned());
        }
        if let Err(error) = services.audit.append(event).await {
            self.out
                .note(&Failure::from(error).details(self.out.locale()).join(" "));
        }
    }
}

impl Services {
    /// Router profiles and clients.
    pub(crate) const fn registry(&self) -> &Arc<RouterRegistry> {
        &self.registry
    }

    /// Audit writer.
    pub(crate) const fn audit_log(&self) -> &AuditLog {
        &self.audit
    }

    /// Encrypted backups.
    pub(crate) const fn backups(&self) -> &Arc<BackupStore> {
        &self.backups
    }

    /// Protected change workflow.
    pub(crate) const fn workflow(&self) -> &Arc<ChangeWorkflow> {
        &self.workflow
    }
}

impl Target {
    /// Profile id.
    pub(crate) fn id(&self) -> &str {
        &self.id
    }

    /// The principal's role narrowed to this router.
    pub(crate) const fn role(&self) -> &Role {
        &self.role
    }

    /// Domain context.
    pub(crate) const fn router(&self) -> &RouterCtx {
        &self.router
    }

    /// Detected identity.
    pub(crate) const fn info(&self) -> &RouterInfo {
        &self.info
    }
}

/// Loads `path`, or the default `kcc.toml` when present, else the defaults.
///
/// # Errors
///
/// Returns read, parse, override or validation failures.
pub(crate) fn load_config(path: Option<&Path>) -> Outcome<Config> {
    let resolved = path.map(Path::to_path_buf).or_else(|| {
        default_config_dir()
            .map(|dir| dir.join("kcc.toml"))
            .filter(|candidate| candidate.exists())
    });
    let mut config = match resolved {
        Some(file) => Config::load(&file)?,
        None => Config::default(),
    };
    drop(config.apply_env_overrides()?);
    config.validate()?;
    Ok(config)
}

/// How long a CLI-armed fail-safe timer runs around a management change.
pub(crate) const MANAGEMENT_TIMER: Duration = Duration::from_secs(300);
