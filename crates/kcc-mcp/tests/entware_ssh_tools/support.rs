//! Shared values of the `entware-ssh` tool tests: the router, the tools, the settings,
//! the SSH fake's userland, what a rig starts with and one call's reply.

use core::{error::Error, time::Duration};

use kcc_app::{
    permissions::{Permission, Role},
    settings::McpConfig,
};
use kcc_testkit::entware_ssh;
use serde_json::Value;

/// Test result.
pub(crate) type TestResult<T = ()> = Result<T, Box<dyn Error>>;

/// The router id.
pub(crate) const ROUTER: &str = "lab-1";

/// The package tool.
pub(crate) const PACKAGES: &str = "kcc_entware_packages";

/// The service tool.
pub(crate) const SERVICES: &str = "kcc_entware_services";

/// Every toolset, `entware-ssh` included.
pub(crate) const EVERY: [&str; 10] = [
    "core",
    "network-write",
    "vpn",
    "dns",
    "system-admin",
    "migration",
    "presets",
    "raw",
    "entware",
    "entware-ssh",
];

/// An administrator with every permission on every router.
pub(crate) fn admin() -> Role {
    Role::new("admin".to_owned(), Permission::ALL, vec!["*".to_owned()])
}

/// `[mcp]` settings registering `toolsets`, destructive operations `allow_destructive`.
pub(crate) fn settings(toolsets: &[&str], allow_destructive: bool) -> McpConfig {
    let mut config = McpConfig::default();
    config.toolsets = toolsets.iter().map(|&name| name.to_owned()).collect();
    config.allow_destructive = allow_destructive;
    config
}

/// Every toolset with destructive operations allowed.
pub(crate) fn every() -> McpConfig {
    settings(&EVERY, true)
}

/// The fake's userland: packages (one upgradable, one installable, one whose version
/// carries an escape sequence and a bell) and two services.
pub(crate) fn userland() -> entware_ssh::Config {
    entware_ssh::Config::default()
        .installed("nano", "7.2-1")
        .installed("evil", "1.0\u{1b}[31m\u{7}-1")
        .upgradable("nano", "7.4-1")
        .installable("htop", "3.3.0-1")
        .service("S50nginx", entware_ssh::Service::new("nginx"))
        .service(
            "S51dropbear",
            entware_ssh::Service::new("dropbear").running(),
        )
}

/// What a rig starts with.
#[expect(
    clippy::field_scoped_visibility_modifiers,
    reason = "the rig reads the setup it starts from"
)]
pub(crate) struct Setup {
    /// The handler's `[mcp]` settings.
    pub(crate) mcp: McpConfig,
    /// The session's role.
    pub(crate) role: Role,
    /// The SSH fake's userland.
    pub(crate) ssh: entware_ssh::Config,
    /// The bound of one read.
    pub(crate) limit: Duration,
}

impl Setup {
    /// `mcp` and `role` over [`userland`], reads bounded by 20 seconds.
    pub(crate) fn new(mcp: McpConfig, role: Role) -> Self {
        Self {
            mcp,
            role,
            ssh: userland(),
            limit: Duration::from_secs(20),
        }
    }

    /// The same with the SSH fake's userland `ssh`.
    pub(crate) fn ssh(self, ssh: entware_ssh::Config) -> Self {
        Self { ssh, ..self }
    }

    /// The same with reads bounded by `limit`.
    pub(crate) fn limit(self, limit: Duration) -> Self {
        Self { limit, ..self }
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
    /// A reply that `failed` or not, with `value`.
    pub(crate) const fn new(failed: bool, value: Value) -> Self {
        Self { failed, value }
    }

    /// The stable error code of a failed call.
    pub(crate) fn error(&self) -> Option<&str> {
        self.failed
            .then_some(&self.value)
            .and_then(|failure| failure.get("error"))
            .and_then(Value::as_str)
    }

    /// The payload of a successful call.
    ///
    /// # Errors
    ///
    /// The payload of a failed call, as text.
    pub(crate) fn ok(&self) -> TestResult<&Value> {
        if self.failed {
            return Err(format!("tool failed: {}", self.value).into());
        }
        Ok(&self.value)
    }
}
