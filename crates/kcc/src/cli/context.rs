//! One invocation's configuration, principal and application services.

extern crate alloc;

use alloc::{collections::BTreeSet, sync::Arc};
use std::path::{Path, PathBuf};

use kcc_app::{
    accounts::{AccountStore, Clock as _, SystemClock},
    audit::{Attempt, AuditEvent, AuditLog, AuditPolicy, request_id},
    backups::{BackupRetention, BackupStore},
    credentials::CredentialStore,
    permissions::{Permission, Role, load_roles},
    persist::StateStore,
    registry::RouterRegistry,
    secrets::{MasterKey, master_key_path},
    settings::{Config, default_config_dir},
    workflow::ChangeWorkflow,
};
use kcc_catalog::Catalog;
use kcc_domain::{
    RouterCtx,
    configuration::{SafetyNet, apply_needs::ApplyNeeds},
};
use kcc_i18n::{bundle::tr, keys};
use kcc_rci::capabilities::RouterInfo;
use serde_json::Value;

use super::{
    args::Cli,
    exit::{Exit, Failure, Outcome},
    outbound,
    output::Out,
    principal::Principal,
};
use crate::server_migrations::append_credential_events;

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
    /// Encrypted kcc-managed router credentials.
    credentials: Arc<CredentialStore>,
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
    /// Correlation id of this run's audit entries.
    request_id: String,
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
            request_id: request_id::next("cli"),
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

    /// Correlation id of this run's audit entries, its change sets' included.
    pub(crate) fn request_id(&self) -> String {
        self.request_id.clone()
    }

    /// Authorizes `permissions` on `routers`; a refusal is audited as `cli.refused`
    /// (`forbidden`) on the first of them.
    ///
    /// # Errors
    /// Returns the principal's permission or scope refusal.
    // NOT cancel-safe: the refusal audit may append after cancellation.
    pub(crate) async fn authorize_audited(
        &self,
        services: &Services,
        permissions: &[Permission],
        routers: &[&str],
    ) -> Outcome<Role> {
        let refusal = match self.principal.authorize(permissions, routers) {
            Ok(role) => return Ok(role),
            Err(refusal) => refusal,
        };
        let router = routers.first().copied();
        self.attempt(services, "cli.refused", router, Attempt::Forbidden)
            .await;
        Err(refusal)
    }

    /// Checks recovery authority and records a handler-level refusal.
    ///
    /// # Errors
    /// Returns the principal's permission or scope refusal.
    // NOT cancel-safe: the refusal audit may append after cancellation.
    pub(crate) async fn authorize_recovery(&self, services: &Services, id: &str) -> Outcome {
        let control = [SafetyNet::CONTROL_PERMISSION];
        drop(self.authorize_audited(services, &control, &[id]).await?);
        Ok(())
    }

    /// Checks the authority an apply with `needs` requires and records a handler-level
    /// refusal.
    ///
    /// # Errors
    /// Returns the principal's permission or scope refusal.
    // NOT cancel-safe: the refusal audit may append after cancellation.
    pub(crate) async fn authorize_apply(
        &self,
        services: &Services,
        id: &str,
        needs: ApplyNeeds,
    ) -> Outcome {
        let required = SafetyNet::apply_permissions(needs);
        match self.authorize_audited(services, &required, &[id]).await {
            Ok(role) => {
                drop(role);
                Ok(())
            }
            Err(failure) => {
                // Check if all required permissions are granted (without router scope check).
                let all_permissions_granted = required
                    .iter()
                    .all(|perm| self.principal.role().grants(*perm));

                // Check if the router is in the principal's scope.
                let router_in_scope = self.principal.sees(id);

                // If all permissions are granted but the router is out of scope,
                // print the router-out-of-scope message instead of a missing permissions list.
                if all_permissions_granted && !router_in_scope {
                    return Err(Failure::message(
                        failure.exit(),
                        keys::CLI_ROUTER_OUT_OF_SCOPE,
                        &[("router", id)],
                    ));
                }

                // Compute the subset of actually missing permissions (without scope check).
                let missing = required
                    .iter()
                    .copied()
                    .filter(|permission| !self.principal.role().grants(*permission))
                    .collect::<BTreeSet<_>>();
                let labels = missing
                    .iter()
                    .filter_map(|permission| {
                        [
                            (Permission::Read, keys::WEB_ADMIN_PERMISSION_READ),
                            (Permission::Write, keys::WEB_ADMIN_PERMISSION_WRITE),
                            (Permission::Save, keys::WEB_ADMIN_PERMISSION_SAVE),
                            (
                                Permission::Destructive,
                                keys::WEB_ADMIN_PERMISSION_DESTRUCTIVE,
                            ),
                            (Permission::Migrate, keys::WEB_ADMIN_PERMISSION_MIGRATE),
                        ]
                        .into_iter()
                        .find(|(known, _key)| known == permission)
                        .map(|(_known, key)| tr(self.out.locale(), key, None))
                    })
                    .collect::<Vec<_>>()
                    .join(", ");
                Err(Failure::message(
                    failure.exit(),
                    keys::CLI_APPLY_RECOVERY_FORBIDDEN,
                    &[("missing", &labels)],
                ))
            }
        }
    }

    /// Opens the router services; contacts no router. A legacy router credential
    /// migrated on this first use is audited by router id.
    ///
    /// # Errors
    ///
    /// Returns registry, key or audit failures.
    // NOT cancel-safe: a migration audit event may be appended after cancellation.
    pub(crate) async fn services(&self) -> Outcome<Services> {
        let key = MasterKey::load_or_create(&master_key_path()?)?;
        let credentials = Arc::new(CredentialStore::new(self.state.clone(), key.duplicate()));
        let migrations = credentials.migrate_all()?;
        let registry = Arc::new(
            RouterRegistry::new(
                self.state.clone(),
                &self.config.routers,
                &self.config.outbound,
            )?
            .with_credentials(Arc::clone(&credentials)),
        );
        for (router, file) in registry.external_password_files()? {
            let path = file.display().to_string();
            self.out.note(&self.out.tr(
                keys::CLI_ROUTER_EXTERNAL_PASSWORD,
                &[("router", &router), ("path", &path)],
            ));
        }
        let audit = AuditLog::spawn_with_policy(
            &self.state,
            AuditPolicy::default().with_retention(self.config.audit.retention),
        )?;
        append_credential_events(&audit, migrations, "cli").await?;
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
            credentials,
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
        )
        .with_max_failures(self.config.web.login_max_failures))
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
        self.target_named(services, id, permissions).await
    }

    /// Authorizes `permissions` on router `id`, then connects to it.
    ///
    /// Refusals are audited and happen before any router request.
    ///
    /// # Errors
    ///
    /// Returns the policy refusal, or connection and detection failures.
    // cancel-safe: connecting and detection only read router state.
    pub(crate) async fn target_named(
        &self,
        services: &Services,
        id: String,
        permissions: &[Permission],
    ) -> Outcome<Target> {
        services.audit.require_alive()?;
        let role = self
            .authorize_audited(services, permissions, &[id.as_str()])
            .await?;
        let url = services.registry.get(&id)?.profile.url;
        let client = services
            .registry
            .client(&id)
            .await
            .map_err(|error| outbound::explained(error, &url))?;
        let info = services
            .registry
            .poll_info(&id)
            .await
            .map_err(|error| outbound::explained(error, &url))?;
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
        let mut event = AuditEvent::new(
            SystemClock::default().unix_seconds(),
            self.principal.actor(),
            action.to_owned(),
        )
        .with_params(params)
        .with_result(outcome.to_owned(), self.request_id());
        if let Some(name) = router {
            event = event.with_router(name.to_owned());
        }
        self.append(services, event).await;
    }

    /// Appends the CLI audit entry of `attempt`, which did not do what it was asked to.
    // NOT cancel-safe: the writer may append after cancellation.
    pub(crate) async fn attempt(
        &self,
        services: &Services,
        action: &str,
        router: Option<&str>,
        attempt: Attempt,
    ) {
        let event = AuditEvent::attempt(
            SystemClock::default().unix_seconds(),
            self.principal.actor(),
            action.to_owned(),
            router.map(str::to_owned),
            attempt,
        )
        .with_request_id(self.request_id());
        self.append(services, event).await;
    }

    /// Passes `confirmation` on, auditing a missing one as refused on `router`.
    ///
    /// # Errors
    ///
    /// Returns the refusal of `confirmation`.
    // NOT cancel-safe: the refusal audit may append after cancellation.
    pub(crate) async fn confirmed(
        &self,
        services: &Services,
        router: &str,
        confirmation: Outcome,
    ) -> Outcome {
        if confirmation.is_err() {
            let reason = Attempt::Refused {
                reason: "confirm_required",
            };
            self.attempt(services, "cli.refused", Some(router), reason)
                .await;
        }
        confirmation
    }

    /// Appends `event`; a failing audit write is reported but does not hide the
    /// command's own result.
    // NOT cancel-safe: the writer may append after cancellation.
    async fn append(&self, services: &Services, event: AuditEvent) {
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

    /// Encrypted kcc-managed router credentials.
    pub(crate) const fn credentials(&self) -> &Arc<CredentialStore> {
        &self.credentials
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
