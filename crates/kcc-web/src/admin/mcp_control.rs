//! What the MCP settings page learns from and asks of the running listeners: the toolsets
//! the MCP server offers, why a change did not apply, and how the listeners started.

use kcc_app::mcp_settings::ListenerKind;

/// One toolset the running MCP server offers.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct McpToolset {
    /// The toolset's name, as `[mcp] toolsets` lists it.
    pub name: String,
    /// Whether turning it on reduces safety (the page asks for the password again).
    pub safety_reducing: bool,
}

impl McpToolset {
    /// The toolset `name`, safety-reducing or not.
    #[inline]
    #[must_use]
    pub const fn new(name: String, safety_reducing: bool) -> Self {
        Self {
            name,
            safety_reducing,
        }
    }
}

/// Why a change of the MCP settings did not apply: a class only, never the text of the
/// failure, which goes to the server log.
///
/// Every class leaves the previous settings in force and `mcp_settings.json` unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum McpRefusal {
    /// `mcp_settings.json` changed since the change was planned; nothing changed.
    #[error("the MCP settings changed since this change was planned")]
    SettingsChanged,
    /// The listener's OAuth or client-certificate sign-in is not available in this build;
    /// nothing changed.
    #[error("the {} listener's sign-in method is not available", name(*.0))]
    SignInUnavailable(ListenerKind),
    /// The listener cannot be built from the settings (address, certificate or
    /// configuration); nothing changed.
    #[error("the {} listener cannot use these settings", name(*.0))]
    Unusable(ListenerKind),
    /// The new listener could not bind its address; the previous one serves again.
    #[error("the {} listener could not bind its address", name(*.0))]
    Bind(ListenerKind),
    /// The new listener stopped before it served; the previous one serves again.
    #[error("the {} listener stopped before it served", name(*.0))]
    Serve(ListenerKind),
    /// The keys and roles could not be installed in the new listener; the previous one
    /// serves again.
    #[error("the {} listener could not load the keys and roles", name(*.0))]
    Register(ListenerKind),
    /// The new listener failed its health check; the previous one serves again.
    #[error("the {} listener failed its health check", name(*.0))]
    Health(ListenerKind),
    /// The live settings could not be applied; the previous ones stay.
    #[error("the live settings could not be applied")]
    Apply,
    /// `mcp_settings.json` could not be written; the previous settings stay.
    #[error("the settings could not be saved")]
    Commit,
    /// A step ended abnormally; the previous settings stay.
    #[error("the change ended abnormally")]
    Failed,
    /// `kcc serve` is stopping; the change did not run or did not finish.
    #[error("kcc serve is stopping")]
    ShuttingDown,
}

impl McpRefusal {
    /// Stable snake-case code of the class, as the audit log records it.
    #[inline]
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::SettingsChanged => "settings_changed",
            Self::SignInUnavailable(_) => "sign_in_unavailable",
            Self::Unusable(_) => "unusable",
            Self::Bind(_) => "bind",
            Self::Serve(_) => "serve",
            Self::Register(_) => "register",
            Self::Health(_) => "health",
            Self::Apply => "apply",
            Self::Commit => "commit",
            Self::Failed => "failed",
            Self::ShuttingDown => "shutting_down",
        }
    }
}

/// How the listeners of `kcc serve` started.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct McpStatus {
    /// The main listener could not start with the saved sign-in settings and started with
    /// kcc.toml's instead.
    pub fallback: bool,
    /// The dedicated listener could not start with the saved settings and was skipped.
    pub skipped: bool,
}

impl McpStatus {
    /// Both listeners started with the saved settings.
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self {
            fallback: false,
            skipped: false,
        }
    }

    /// The same status with the main listener's start-up fallback.
    #[inline]
    #[must_use]
    pub const fn with_fallback(mut self) -> Self {
        self.fallback = true;
        self
    }

    /// The same status with the dedicated listener skipped at start.
    #[inline]
    #[must_use]
    pub const fn with_skipped(mut self) -> Self {
        self.skipped = true;
        self
    }
}

/// The listener's name in log and error text.
const fn name(kind: ListenerKind) -> &'static str {
    match kind {
        ListenerKind::Main => "main",
        ListenerKind::Dedicated | _ => "dedicated",
    }
}
