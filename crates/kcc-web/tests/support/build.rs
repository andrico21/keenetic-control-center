//! The Web UI over fake routers: the fleet beside the state, accounts and audit log.

extern crate alloc;

use alloc::sync::Arc;
use core::{net::SocketAddr, time::Duration};

use kcc_app::{
    backups::BackupStore,
    credentials::CredentialStore,
    jobs::JobRunner,
    permissions::{Permission, Role, built_in_roles},
    poller::Poller,
    registry::{ManagedRouterProfile, RouterRegistry},
    secrets::MasterKey,
    settings::{BackupsConfig, OutboundConfig},
    workflow::ChangeWorkflow,
};
use kcc_testkit::{DEFAULT_LOGIN, DEFAULT_PASSWORD, FakeRouter, Handle};
use kcc_web::{
    fleet::{BackupServices, FleetServices},
    session::CookieSecurity,
    web_router,
};
use url::Url;

use super::{
    base::{Account, Core, Frozen},
    outcome::TestResult,
    web::Fixture,
};

/// What the Web UI gets beside the fleet, and how its browser posts.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Wiring {
    /// Router pages: backup pages and background jobs; htmx posts.
    Pages,
    /// Wizards: background jobs, no backup pages; htmx posts.
    Wizards,
    /// Fleet management: router credentials sealed in the credential store, neither jobs
    /// nor backup pages; native form posts.
    Fleet,
}

/// The Web UI over fake routers.
#[expect(
    clippy::field_scoped_visibility_modifiers,
    reason = "each suite sets what differs and takes the rest from the default"
)]
pub(crate) struct Setup {
    /// The accounts.
    pub(crate) accounts: Vec<Account<'static>>,
    /// The roles.
    pub(crate) roles: Vec<Role>,
    /// The fake routers by profile id, registered in order.
    pub(crate) routers: Vec<(&'static str, FakeRouter)>,
    /// The outbound policy of the registry.
    pub(crate) outbound: OutboundConfig,
    /// The Unix second of the account and session clock.
    pub(crate) now: u64,
    /// The services beside the fleet.
    pub(crate) wiring: Wiring,
}

impl Default for Setup {
    /// One account per built-in role, `outsider` (every permission on `lab-*` routers
    /// only), `raw-writer`, `rawdes`, `writer` and `ukrainian` (an administrator), and no
    /// routers yet.
    fn default() -> Self {
        let mut outbound = OutboundConfig::default();
        outbound.allow_loopback = true;
        Self {
            accounts: [
                "viewer",
                "operator",
                "admin",
                "outsider",
                "raw-writer",
                "rawdes",
                "writer",
            ]
            .map(|name| (name, name, None))
            .into_iter()
            .chain([("ukrainian", "admin", Some("uk"))])
            .collect(),
            roles: pages_roles(),
            routers: Vec::new(),
            outbound,
            now: 1_700_000_000,
            wiring: Wiring::Pages,
        }
    }
}

impl Setup {
    /// Serves and registers the routers and builds the Web UI.
    // NOT cancel-safe: the fake routers and the job runner start before it returns.
    pub(crate) async fn build(self) -> TestResult<Fixture> {
        let core = Core::new(Arc::new(Frozen(self.now)), &self.accounts)?;
        let state = core.state.clone();
        let credentials = Arc::new(CredentialStore::new(state.clone(), MasterKey::generate()?));
        let unsealed = RouterRegistry::new(state.clone(), &[], &self.outbound)?;
        let registry = Arc::new(match self.wiring {
            Wiring::Fleet => unsealed.with_credentials(Arc::clone(&credentials)),
            Wiring::Pages | Wiring::Wizards => unsealed,
        });
        let handles = register(&core, &registry, self.routers).await?;
        let backups = Arc::new(BackupStore::new(state.clone(), master_key()));
        let audit = core.audit.clone();
        let workflow = ChangeWorkflow::new(
            state.clone(),
            Arc::clone(&registry),
            Arc::clone(&backups),
            audit.clone(),
        );
        let fleet = core
            .web(
                self.roles,
                (Duration::from_secs(3_600), Duration::from_secs(36_000)),
                CookieSecurity::LoopbackHttp,
            )
            .with_fleet(FleetServices {
                registry: Arc::clone(&registry),
                poller: Poller::new(Arc::clone(&registry)),
                workflow,
                credentials,
                update_check: None,
                backups: (self.wiring == Wiring::Pages)
                    .then(|| BackupServices::new(backups, BackupsConfig::default())),
            });
        let web = match self.wiring {
            Wiring::Pages | Wiring::Wizards => {
                fleet.with_jobs(JobRunner::open(state, Arc::clone(&registry), audit).await?)
            }
            Wiring::Fleet => fleet,
        };
        Ok(Fixture {
            directory: core.directory,
            router: web_router(web),
            registry,
            handles,
            htmx: self.wiring != Wiring::Fleet,
        })
    }
}

/// Serves `routers` and registers each with the fixture's router password file.
// NOT cancel-safe: a router may be served before cancellation.
async fn register(
    core: &Core,
    registry: &RouterRegistry,
    routers: Vec<(&'static str, FakeRouter)>,
) -> TestResult<Vec<(&'static str, Handle)>> {
    let password_file =
        kcc_testkit::write_secret_file(core.directory.path(), "router-password", DEFAULT_PASSWORD)?;
    let admin = admin()?;
    let mut handles = Vec::new();
    for (id, fake) in routers {
        let (address, handle) = fake.serve(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let profile = ManagedRouterProfile::new(
            id.to_owned(),
            Url::parse(&format!("http://{address}"))?,
            DEFAULT_LOGIN.to_owned(),
            password_file.clone(),
        );
        registry.create(&admin, profile).await?;
        handles.push((id, handle));
    }
    Ok(handles)
}

/// The built-in roles and the router pages' own: `writer`, `rawdes`, `outsider` (every
/// permission on `lab-*` routers) and `raw-writer`.
fn pages_roles() -> Vec<Role> {
    let every = || vec!["*".to_owned()];
    built_in_roles()
        .into_iter()
        .chain([
            Role::new(
                "writer".to_owned(),
                [Permission::Read, Permission::Write],
                every(),
            ),
            Role::new(
                "rawdes".to_owned(),
                [
                    Permission::Read,
                    Permission::RawRci,
                    Permission::Destructive,
                ],
                every(),
            ),
            Role::new(
                "outsider".to_owned(),
                Permission::ALL,
                vec!["lab-*".to_owned()],
            ),
            Role::new(
                "raw-writer".to_owned(),
                [Permission::Read, Permission::Write, Permission::RawRci],
                every(),
            ),
        ])
        .collect()
}

/// The built-in administrator role.
pub(crate) fn admin() -> TestResult<Role> {
    built_in_roles()
        .into_iter()
        .find(|role| role.name == "admin")
        .ok_or_else(|| "no admin role".into())
}

/// The fixture's backup key.
pub(crate) fn master_key() -> MasterKey {
    MasterKey::from_bytes([7_u8; 32])
}
