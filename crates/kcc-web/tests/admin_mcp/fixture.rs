//! The MCP settings page over a fleet without routers, its administration services built
//! from a kcc.toml text and environment, and the stand-in listeners.

extern crate alloc;

use alloc::sync::Arc;
use std::{fs, path::PathBuf};

use axum::Router;
use kcc_app::{
    audit::AuditEntry,
    mcp_settings::{EnvOverrides, McpBase},
    permissions::{Permission, Role},
    persist::StateStore,
    settings::{Config, ConfigError},
};
use kcc_web::{
    admin::{AdminServices, ServerFacts, mcp_control::McpStatus},
    web_router,
};

use crate::{
    stub::Stub,
    support::{
        build::{Setup, Wiring},
        outcome::TestResult,
        web::Fixture,
    },
};

/// The administrators signing in in another language than English, with their locales.
pub(crate) const LOCALIZED: [(&str, &str); 5] = [
    ("russian", "ru"),
    ("ukrainian", "uk"),
    ("german", "de"),
    ("belarusian", "be"),
    ("kazakh", "kk"),
];

/// The Web UI with the MCP settings page.
#[expect(
    clippy::field_scoped_visibility_modifiers,
    reason = "the requests in the client module send through the router"
)]
pub(crate) struct Mcp {
    /// The fleet fixture: state directory, accounts and audit log.
    web: Fixture,
    /// The Web UI with the administration services and the stand-in attached.
    pub(super) router: Router,
    /// The state directory.
    store: StateStore,
    /// The stand-in listeners, when attached.
    stub: Option<Arc<Stub>>,
}

impl Mcp {
    /// The page over `toml` with the `KCC_*` variables `env`, with stand-in listeners
    /// reporting `status`, or none. Accounts: one per built-in role, `una` (Read and
    /// `ManageUsers`), `mia` (Read and `ManageMcp`) and the administrators of
    /// [`LOCALIZED`].
    // NOT cancel-safe: setup starts the fleet's tasks.
    pub(crate) async fn build(
        toml: &str,
        env: &[(&str, &str)],
        status: Option<McpStatus>,
    ) -> TestResult<Self> {
        let every = || vec!["*".to_owned()];
        let mut setup = Setup {
            wiring: Wiring::Fleet,
            ..Setup::default()
        };
        setup.roles.extend([
            Role::new(
                "useradmin".to_owned(),
                [Permission::Read, Permission::ManageUsers],
                every(),
            ),
            Role::new(
                "mcpadmin".to_owned(),
                [Permission::Read, Permission::ManageMcp],
                every(),
            ),
        ]);
        setup.accounts.retain(|(name, _, _)| *name != "ukrainian");
        setup
            .accounts
            .extend([("una", "useradmin", None), ("mia", "mcpadmin", None)]);
        setup.accounts.extend(
            LOCALIZED
                .iter()
                .map(|(name, locale)| (*name, "admin", Some(*locale))),
        );
        let web = setup.build().await?;
        let store = StateStore::open(&web.state_dir())?;
        let mut config = Config::from_toml_str(toml)?;
        let reports = config.apply_kcc_env_overrides_with(|var| {
            Ok::<_, ConfigError>(
                env.iter()
                    .find(|(name, _)| *name == var)
                    .map(|(_, value)| (*value).to_owned()),
            )
        })?;
        let base = McpBase::new(&config, &EnvOverrides::from_reports(&reports));
        let mut state = web.state().clone().with_admin(AdminServices {
            state: store.clone(),
            reload: None,
            server: ServerFacts::from_config("9.9.9".to_owned(), &config, &base.effective(&store)?),
            mcp: base,
        });
        let stub = status.map(|reported| Stub::new(store.clone(), reported));
        if let Some(attached) = &stub {
            state = state.with_mcp_control(Arc::<Stub>::clone(attached));
        }
        Ok(Self {
            router: web_router(state),
            store,
            stub,
            web,
        })
    }

    /// The page over the defaults with stand-in listeners that started normally.
    // NOT cancel-safe: setup starts the fleet's tasks.
    pub(crate) async fn plain() -> TestResult<Self> {
        Self::build("", &[], Some(McpStatus::new())).await
    }

    /// The state directory.
    pub(crate) const fn store(&self) -> &StateStore {
        &self.store
    }

    /// The stand-in listeners.
    pub(crate) fn stub(&self) -> TestResult<&Stub> {
        Ok(self.stub.as_deref().ok_or("no stand-in attached")?)
    }

    /// `<state>/<name>`.
    pub(crate) fn state_file(&self, name: &str) -> PathBuf {
        self.store.dir().join(name)
    }

    /// The bytes of `<state>/mcp_settings.json`, empty when absent.
    pub(crate) fn settings_bytes(&self) -> TestResult<Vec<u8>> {
        let path = self.state_file("mcp_settings.json");
        Ok(if path.exists() {
            fs::read(path)?
        } else {
            Vec::new()
        })
    }

    /// The audit entries of `action`, once every queued entry is written.
    pub(crate) async fn audited(&self, action: &str) -> TestResult<Vec<AuditEntry>> {
        let queued = self.web.audit_flushed().await;
        if queued != 0 {
            return Err(format!("{queued} audit entries still queued").into());
        }
        Ok(self
            .web
            .audit()?
            .into_iter()
            .filter(|entry| entry.action == action)
            .collect())
    }

    /// The whole audit log as text, once every queued entry is written.
    pub(crate) async fn audit_text(&self) -> TestResult<String> {
        let queued = self.web.audit_flushed().await;
        if queued != 0 {
            return Err(format!("{queued} audit entries still queued").into());
        }
        Ok(serde_json::to_string(
            &self
                .web
                .audit()?
                .into_iter()
                .map(|entry| {
                    (
                        entry.action,
                        entry.target,
                        entry.params_redacted,
                        entry.outcome,
                    )
                })
                .collect::<Vec<_>>(),
        )?)
    }
}
