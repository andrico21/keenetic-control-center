//! An in-process MCP session against fake routers registered in a real registry.
#![expect(
    clippy::missing_errors_doc,
    reason = "test support returns the boxed error of whatever setup step failed"
)]

use alloc::{collections::BTreeSet, sync::Arc};
use core::{error::Error, time::Duration};
use std::path::PathBuf;

use kcc_app::{
    audit::{AuditEntry, AuditLog, verify_chain},
    backups::BackupStore,
    jobs::JobRunner,
    permissions::{Permission, Role},
    persist::StateStore,
    poller::Poller,
    registry::{ManagedRouterProfile, RouterRegistry},
    role_source::RoleSource,
    secrets::MasterKey,
    settings::{McpConfig, OutboundConfig, PrivacyConfig},
    workflow::ChangeWorkflow,
};
use kcc_mcp::KccMcp;
use kcc_migrate::presets::store::PresetStore;
use kcc_testkit::{DEFAULT_LOGIN, DEFAULT_PASSWORD, FakeRouter, Handle};
use rmcp::{
    ClientHandler, ServiceExt as _,
    model::{
        CallToolRequestParams, NumberOrString, ProgressNotificationParam, ProgressToken,
        RequestMetaObject,
    },
    service::{NotificationContext, RoleClient, RunningService},
};
use serde_json::Value;
use tempfile::TempDir;
use tokio::{io::duplex, sync::mpsc, time::timeout};
use url::Url;

/// Test result.
pub(crate) type TestResult<T = ()> = Result<T, Box<dyn Error>>;

/// A client that records every progress notification it receives.
#[derive(Debug, Clone)]
pub(crate) struct Recorder(mpsc::UnboundedSender<ProgressNotificationParam>);

impl ClientHandler for Recorder {
    async fn on_progress(
        &self,
        params: ProgressNotificationParam,
        _context: NotificationContext<RoleClient>,
    ) {
        drop(self.0.send(params));
    }
}

/// One tool call's outcome: whether it failed and its JSON payload.
#[derive(Debug)]
pub(crate) struct Reply {
    /// Whether the tool reported an error.
    failed: bool,
    /// The JSON text content.
    value: Value,
}

impl Reply {
    /// The stable error code of a failed call.
    pub(crate) fn error(&self) -> Option<&str> {
        self.failure()
            .and_then(|failure| failure.get("error"))
            .and_then(Value::as_str)
    }

    /// The JSON payload of a failed call.
    pub(crate) fn failure(&self) -> Option<&Value> {
        self.failed.then_some(&self.value)
    }

    /// The payload of a successful call.
    pub(crate) fn value(&self) -> TestResult<&Value> {
        if self.failed {
            return Err(format!("tool failed: {}", self.value).into());
        }
        Ok(&self.value)
    }
}

/// Routers, services, and one connected MCP client session.
#[expect(
    clippy::field_scoped_visibility_modifiers,
    clippy::partial_pub_fields,
    reason = "resource tests drive resources/list and resources/read on the same session"
)]
#[expect(
    unreachable_pub,
    reason = "integration tests compile this shared support module as their crate-local harness"
)]
pub struct Lab {
    /// Temporary state.
    directory: TempDir,
    /// Router handles by profile id.
    routers: Vec<(String, Handle)>,
    /// Registry retained for test-only out-of-band router changes.
    pub registry: Arc<RouterRegistry>,
    /// The client session.
    pub(crate) client: RunningService<RoleClient, Recorder>,
    /// Progress notifications received.
    progress: mpsc::UnboundedReceiver<ProgressNotificationParam>,
    /// Live application roles retained for late permission edits.
    pub(crate) roles: RoleSource,
    /// The server's job runner, for jobs a test starts itself.
    pub(crate) jobs: Arc<JobRunner>,
}

/// An administrator with every permission on every router.
pub(crate) fn admin() -> Role {
    Role::new("admin".to_owned(), Permission::ALL, vec!["*".to_owned()])
}

/// Every permission, only on routers matching `lab-*`.
pub(crate) fn lab_only() -> Role {
    Role::new("lab".to_owned(), Permission::ALL, vec!["lab-*".to_owned()])
}

impl Lab {
    /// Serves `routers`, registers them, and connects a session whose stdio identity has
    /// `role`; every toolset is enabled and destructive operations are allowed.
    pub(crate) async fn start(routers: Vec<(&str, FakeRouter)>, role: Role) -> TestResult<Self> {
        Self::start_with_destructive(routers, role, true).await
    }

    /// Starts a session with an explicit destructive-operation switch.
    pub(crate) async fn start_with_destructive(
        routers: Vec<(&str, FakeRouter)>,
        role: Role,
        allow_destructive: bool,
    ) -> TestResult<Self> {
        Self::start_with_privacy(routers, role, allow_destructive, PrivacyConfig::default()).await
    }

    /// Starts a session with an explicit destructive-operation switch and privacy settings.
    pub(crate) async fn start_with_privacy(
        routers: Vec<(&str, FakeRouter)>,
        role: Role,
        allow_destructive: bool,
        privacy: PrivacyConfig,
    ) -> TestResult<Self> {
        let directory = TempDir::new()?;
        let state = StateStore::open(&directory.path().join("state"))?;
        let mut outbound = OutboundConfig::default();
        outbound.allow_loopback = true;
        let registry = Arc::new(RouterRegistry::new(state.clone(), &[], &outbound)?);
        let mut handles = Vec::new();
        for (id, fake) in routers {
            let (address, handle) = fake.serve(([127, 0, 0, 1], 0).into()).await?;
            let password = kcc_testkit::write_secret_file(
                directory.path(),
                &format!("{id}-password"),
                DEFAULT_PASSWORD,
            )?;
            let profile = ManagedRouterProfile::new(
                id.to_owned(),
                Url::parse(&format!("http://{address}"))?,
                DEFAULT_LOGIN.to_owned(),
                password,
            );
            registry.create(&admin(), profile).await?;
            handles.push((id.to_owned(), handle));
        }
        let backups = Arc::new(BackupStore::new(
            state.clone(),
            MasterKey::from_bytes([5_u8; 32]),
        ));
        let audit = AuditLog::spawn(&state)?;
        let workflow =
            ChangeWorkflow::new(state.clone(), Arc::clone(&registry), backups, audit.clone());
        let presets = PresetStore::new(state.clone(), MasterKey::from_bytes([6_u8; 32]));
        let jobs = JobRunner::open(state, Arc::clone(&registry), audit.clone()).await?;
        let poller = Poller::new(Arc::clone(&registry));
        let mut config = McpConfig::default();
        config.toolsets = [
            "core",
            "network-write",
            "vpn",
            "dns",
            "system-admin",
            "migration",
            "presets",
            "raw",
        ]
        .map(str::to_owned)
        .to_vec();
        config.allow_destructive = allow_destructive;
        let roles = RoleSource::new(vec![admin(), lab_only(), role.clone()]);
        let server = KccMcp::new(
            config,
            privacy,
            Arc::clone(&registry),
            workflow,
            Arc::clone(&jobs),
            poller,
            vec![admin(), lab_only()],
            role,
        )
        .with_role_source(roles.clone())
        .with_audit(audit)
        .with_presets(presets);
        let (server_io, client_io) = duplex(1 << 20);
        drop(tokio::spawn(async move {
            if let Ok(running) = server.serve(server_io).await {
                drop(running.waiting().await);
            }
        }));
        let (sender, progress) = mpsc::unbounded_channel();
        let client = Recorder(sender).serve(client_io).await?;
        Ok(Self {
            directory,
            routers: handles,
            registry,
            client,
            progress,
            roles,
            jobs,
        })
    }

    /// Names of the tools the session lists.
    pub(crate) async fn tool_names(&self) -> TestResult<BTreeSet<String>> {
        drop(self.roles.current());
        Ok(self
            .client
            .list_all_tools()
            .await?
            .into_iter()
            .map(|tool| tool.name.into_owned())
            .collect())
    }

    /// Requests router `id` has received.
    pub(crate) fn requests(&self, id: &str) -> TestResult<u64> {
        Ok(self.router(id)?.request_count())
    }

    /// The fake router `id`.
    pub(crate) fn router(&self, id: &str) -> TestResult<&Handle> {
        self.routers
            .iter()
            .find(|(name, _handle)| name == id)
            .map(|(_name, handle)| handle)
            .ok_or_else(|| format!("no router {id}").into())
    }

    /// Calls `tool`, optionally with a progress token.
    pub(crate) async fn call(
        &self,
        tool: &str,
        arguments: Value,
        progress: bool,
    ) -> TestResult<Reply> {
        let Value::Object(object) = arguments else {
            return Err("arguments must be an object".into());
        };
        let mut params = CallToolRequestParams::new(tool.to_owned()).with_arguments(object);
        if progress {
            params.meta = Some(RequestMetaObject::with_progress_token(ProgressToken(
                NumberOrString::Number(7),
            )));
        }
        let result = self.client.call_tool(params).await?;
        let text = result
            .content
            .first()
            .and_then(|content| content.as_text())
            .map(|content| content.text.clone())
            .ok_or("tool returned no text")?;
        Ok(Reply {
            failed: result.is_error == Some(true),
            value: serde_json::from_str(&text)?,
        })
    }

    /// Waits up to five seconds for the first progress notification, then drains the rest.
    pub(crate) async fn progress_received(&mut self) -> Vec<ProgressNotificationParam> {
        let mut received = Vec::new();
        if let Ok(Some(first)) = timeout(Duration::from_secs(5), self.progress.recv()).await {
            received.push(first);
        }
        while let Ok(params) = self.progress.try_recv() {
            received.push(params);
        }
        received
    }

    /// Verifies the hash chain, then returns every audit entry.
    pub(crate) fn audit(&self) -> TestResult<Vec<AuditEntry>> {
        Ok(verify_chain(&self.state_dir())?)
    }

    /// The state directory.
    pub(crate) fn state_dir(&self) -> PathBuf {
        self.directory.path().join("state")
    }

    /// Ends the session and stops every router.
    pub(crate) async fn stop(self) -> TestResult {
        drop(self.client.cancel().await?);
        drop(self.jobs);
        drop(self.registry);
        for (_id, handle) in self.routers {
            handle.shutdown().await?;
        }
        Ok(())
    }
}
