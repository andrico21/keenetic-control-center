//! The Web UI's view of the supervisor: the MCP settings page hands its planned changes
//! to [`ListenerSupervisor`] and reads how the listeners started, through kcc-web's
//! [`McpControl`].

use kcc_app::mcp_settings::{Candidate, ListenerKind};
use kcc_mcp::registry::definitions;
use kcc_web::admin::{
    McpChange, McpControl,
    mcp_control::{McpRefusal, McpStatus, McpToolset},
};

use super::{
    ListenerError, ListenerSupervisor, Restarted, RevertReason, Status, build::BuildError,
};

/// [`McpControl`] over a [`ListenerSupervisor`] handle.
#[derive(Debug, Clone)]
pub(crate) struct WebHandle {
    /// The supervisor's queue and status.
    supervisor: ListenerSupervisor,
}

impl WebHandle {
    /// The page's control of `supervisor`.
    pub(crate) const fn new(supervisor: ListenerSupervisor) -> Self {
        Self { supervisor }
    }
}

impl McpControl for WebHandle {
    #[inline]
    fn apply_live(&self, candidate: Candidate) -> McpChange {
        let change = self.supervisor.apply_live(candidate);
        // cancel-safe: only awaits the supervisor's reply; the change runs there.
        Box::pin(async move { change.await.map_err(|error| refused(&error)) })
    }

    #[inline]
    fn restart(&self, candidate: Candidate) -> McpChange {
        let change = self.supervisor.restart(candidate);
        // cancel-safe: only awaits the supervisor's reply; the change runs there.
        Box::pin(async move {
            match change.await {
                Ok(Restarted::Applied) => Ok(()),
                Ok(Restarted::Reverted(reason)) => Err(reverted(&reason)),
                Err(error) => Err(refused(&error)),
            }
        })
    }

    #[inline]
    fn replace_client_ca(&self, pem: Vec<u8>, confirmed: bool) -> McpChange {
        let change = self.supervisor.replace_client_ca(pem, confirmed);
        // cancel-safe: only awaits the supervisor's reply; the change runs there.
        Box::pin(async move {
            match change.await {
                Ok(Restarted::Applied) => Ok(()),
                Ok(Restarted::Reverted(reason)) => Err(reverted(&reason)),
                Err(error) => Err(refused(&error)),
            }
        })
    }

    #[inline]
    fn status(&self) -> McpStatus {
        reported(&self.supervisor.status())
    }

    #[inline]
    fn toolsets(&self) -> Vec<McpToolset> {
        offered()
    }
}

/// The start-up fallbacks of `status`, as the page shows them.
const fn reported(status: &Status) -> McpStatus {
    let mut reported = McpStatus::new();
    if status.fallback.is_some() {
        reported = reported.with_fallback();
    }
    if status.skipped.is_some() {
        reported = reported.with_skipped();
    }
    reported
}

/// Every toolset the MCP server offers, with whether turning it on reduces safety.
fn offered() -> Vec<McpToolset> {
    definitions::toolsets()
        .map(|toolset| McpToolset::new(toolset.name.to_owned(), toolset.safety_reducing))
        .collect()
}

/// The listener a supervisor error names.
fn kind(listener: &str) -> ListenerKind {
    if listener == super::name(ListenerKind::Main) {
        ListenerKind::Main
    } else {
        ListenerKind::Dedicated
    }
}

/// The class of a change refused before any listener stopped; its text goes to the log.
fn refused(error: &ListenerError) -> McpRefusal {
    tracing::warn!(%error, "MCP settings change not applied");
    match error {
        ListenerError::SettingsChanged => McpRefusal::SettingsChanged,
        ListenerError::Build {
            listener,
            source: BuildError::SignInUnavailable { listener: _ },
        } => McpRefusal::SignInUnavailable(kind(listener)),
        ListenerError::Build {
            listener,
            source: _,
        } => McpRefusal::Unusable(kind(listener)),
        ListenerError::Apply(_) => McpRefusal::Apply,
        ListenerError::Commit(_) => McpRefusal::Commit,
        ListenerError::ShuttingDown => McpRefusal::ShuttingDown,
        ListenerError::ConfirmationRequired => McpRefusal::ConfirmationRequired,
        ListenerError::Settings(_)
        | ListenerError::RestartRequired
        | ListenerError::Task(_)
        | ListenerError::ClientCa(_) => McpRefusal::Failed,
    }
}

/// The class of a reverted restart; its text goes to the log.
fn reverted(reason: &RevertReason) -> McpRefusal {
    tracing::warn!(?reason, "MCP listener restart reverted");
    match reason {
        RevertReason::Bind {
            listener,
            reason: _,
        } => McpRefusal::Bind(*listener),
        RevertReason::Serve {
            listener,
            reason: _,
        } => McpRefusal::Serve(*listener),
        RevertReason::Register {
            listener,
            reason: _,
        } => McpRefusal::Register(*listener),
        RevertReason::Health {
            listener,
            reason: _,
        } => McpRefusal::Health(*listener),
        RevertReason::Apply(_) => McpRefusal::Apply,
        RevertReason::Commit(_) => McpRefusal::Commit,
        RevertReason::Task(_) => McpRefusal::Failed,
    }
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use kcc_app::mcp_settings::{ListenerKind, SettingsError, client_ca::CaError};
    use kcc_mcp::registry::definitions;
    use kcc_web::admin::{
        ReloadError,
        mcp_control::{McpRefusal, McpStatus},
    };

    use super::{offered, refused, reported, reverted};
    use crate::server_listeners::{ListenerError, RevertReason, Status, build::BuildError};

    /// Todo 27: refusals keep their class and listener.
    ///
    /// A listener whose sign-in method this build lacks, and one that cannot be built
    /// otherwise, are told apart per listener; the other refusals keep their class (todo
    /// 28: an unconfirmed client CA replacement asks for the password).
    #[test]
    fn refusals_keep_their_class_and_listener() {
        let cases = [
            (ListenerError::SettingsChanged, McpRefusal::SettingsChanged),
            (
                ListenerError::Build {
                    listener: "main",
                    source: BuildError::SignInUnavailable { listener: "main" },
                },
                McpRefusal::SignInUnavailable(ListenerKind::Main),
            ),
            (
                ListenerError::Build {
                    listener: "dedicated",
                    source: BuildError::SignInUnavailable {
                        listener: "dedicated",
                    },
                },
                McpRefusal::SignInUnavailable(ListenerKind::Dedicated),
            ),
            (
                ListenerError::Build {
                    listener: "dedicated",
                    source: BuildError::PlaintextBeyondLoopback,
                },
                McpRefusal::Unusable(ListenerKind::Dedicated),
            ),
            (
                ListenerError::Apply(ReloadError::NotReady),
                McpRefusal::Apply,
            ),
            (ListenerError::RestartRequired, McpRefusal::Failed),
            (ListenerError::ShuttingDown, McpRefusal::ShuttingDown),
            (
                ListenerError::Commit(SettingsError::RevisionExhausted),
                McpRefusal::Commit,
            ),
            (
                ListenerError::Settings(SettingsError::RevisionExhausted),
                McpRefusal::Failed,
            ),
            (ListenerError::Task("join".to_owned()), McpRefusal::Failed),
            (
                ListenerError::ConfirmationRequired,
                McpRefusal::ConfirmationRequired,
            ),
            (ListenerError::ClientCa(CaError::NotPem), McpRefusal::Failed),
            (
                ListenerError::Build {
                    listener: "main",
                    source: BuildError::ClientCa("gone".to_owned()),
                },
                McpRefusal::Unusable(ListenerKind::Main),
            ),
        ];
        for (error, class) in cases {
            assert_eq!(refused(&error), class, "{error}");
        }
    }

    /// Todo 27: every revert names its step and listener.
    #[test]
    fn reverts_name_their_step_and_listener() {
        let text = || "kit text".to_owned();
        let cases = [
            (
                RevertReason::Bind {
                    listener: ListenerKind::Dedicated,
                    reason: text(),
                },
                McpRefusal::Bind(ListenerKind::Dedicated),
            ),
            (
                RevertReason::Serve {
                    listener: ListenerKind::Main,
                    reason: text(),
                },
                McpRefusal::Serve(ListenerKind::Main),
            ),
            (
                RevertReason::Register {
                    listener: ListenerKind::Main,
                    reason: text(),
                },
                McpRefusal::Register(ListenerKind::Main),
            ),
            (
                RevertReason::Health {
                    listener: ListenerKind::Dedicated,
                    reason: text(),
                },
                McpRefusal::Health(ListenerKind::Dedicated),
            ),
            (
                RevertReason::Apply(ReloadError::NotReady),
                McpRefusal::Apply,
            ),
            (
                RevertReason::Commit(SettingsError::RevisionExhausted),
                McpRefusal::Commit,
            ),
            (RevertReason::Task(text()), McpRefusal::Failed),
        ];
        for (reason, class) in cases {
            assert_eq!(reverted(&reason), class, "{class:?}");
        }
    }

    /// Todo 27: the page is told about each start-up fallback the supervisor recorded,
    /// and about none it did not.
    #[test]
    fn start_up_fallbacks_reach_the_page() {
        let note = || Some("why".to_owned());
        let cases = [
            (Status::default(), McpStatus::new()),
            (
                Status {
                    fallback: note(),
                    ..Status::default()
                },
                McpStatus::new().with_fallback(),
            ),
            (
                Status {
                    skipped: note(),
                    ..Status::default()
                },
                McpStatus::new().with_skipped(),
            ),
            (
                Status {
                    fallback: note(),
                    skipped: note(),
                    ..Status::default()
                },
                McpStatus::new().with_fallback().with_skipped(),
            ),
        ];
        for (status, page) in cases {
            assert_eq!(reported(&status), page, "{status:?}");
        }
    }

    /// Todo 27: the page offers every toolset of the registry with the registry's safety
    /// mark, so turning on `raw` (or `entware-ssh`, once the registry has it) asks for the
    /// password.
    #[test]
    fn toolsets_keep_their_safety_mark() {
        let offered: Vec<(String, bool)> = offered()
            .into_iter()
            .map(|toolset| (toolset.name, toolset.safety_reducing))
            .collect();
        let registry: Vec<(String, bool)> = definitions::toolsets()
            .map(|toolset| (toolset.name.to_owned(), toolset.safety_reducing))
            .collect();
        assert_eq!(offered, registry);
        let marked = |name: &str| offered.contains(&(name.to_owned(), true));
        assert!(marked("raw"), "raw reduces safety: {offered:?}");
        if definitions::toolset("entware-ssh").is_some() {
            assert!(
                marked("entware-ssh"),
                "entware-ssh reduces safety: {offered:?}"
            );
        }
    }
}
