//! Registry descriptions and dynamic routes of the backup tools.

use core::future::ready;

use kcc_app::permissions::Permission;
use rmcp::handler::server::{common::schema_for_type, router::tool::ToolRoute};

use super::{
    backups::{self, DiffInput, RouterInput},
    state,
};
use crate::{
    KccMcp,
    registry::definitions::ToolDescription,
    support::route::{ToolFuture, route},
};

/// The configuration-state and backup tools.
#[derive(Clone, Copy)]
enum Tool {
    /// `kcc_config_state`.
    ConfigState,
    /// `kcc_config_save`.
    ConfigSave,
    /// `kcc_backup_create`.
    BackupCreate,
    /// `kcc_backup_list`.
    BackupList,
    /// `kcc_backup_diff`.
    BackupDiff,
}

impl Tool {
    /// Every tool, in registry order.
    const ALL: [Self; 5] = [
        Self::ConfigState,
        Self::ConfigSave,
        Self::BackupCreate,
        Self::BackupList,
        Self::BackupDiff,
    ];

    /// The tool's registry description.
    const fn description(self) -> ToolDescription {
        match self {
            Self::ConfigState => ToolDescription::single(
                "kcc_config_state",
                "Read unsaved state, fail-safe state, and the last change",
                "core",
                Permission::Read,
                (true, false, true),
            ),
            Self::ConfigSave => ToolDescription::single(
                "kcc_config_save",
                "Explicitly save the router running configuration",
                "core",
                Permission::Save,
                (false, false, true),
            ),
            Self::BackupCreate => ToolDescription::single(
                "kcc_backup_create",
                "Store the router's startup configuration as an encrypted backup",
                "system-admin",
                Permission::Write,
                (false, false, false),
            ),
            Self::BackupList => ToolDescription::single(
                "kcc_backup_list",
                "List the router's encrypted backups",
                "system-admin",
                Permission::Read,
                (true, false, true),
            ),
            Self::BackupDiff => ToolDescription::single(
                "kcc_backup_diff",
                "Diff two backups with secrets redacted",
                "system-admin",
                Permission::Read,
                (true, false, true),
            ),
        }
    }

    /// The tool's route: its schema and handler.
    fn route(self) -> ToolRoute<KccMcp> {
        let description = self.description();
        match self {
            Self::ConfigState => route(
                &description,
                schema_for_type::<RouterInput>(),
                |server, arguments, _progress| -> ToolFuture<'_> {
                    Box::pin(state::config_state(server, arguments))
                },
            ),
            Self::ConfigSave => route(
                &description,
                schema_for_type::<RouterInput>(),
                |server, arguments, _progress| -> ToolFuture<'_> {
                    Box::pin(state::config_save(server, arguments))
                },
            ),
            Self::BackupCreate => route(
                &description,
                schema_for_type::<RouterInput>(),
                |server, arguments, _progress| -> ToolFuture<'_> {
                    Box::pin(backups::create(server, arguments))
                },
            ),
            Self::BackupList => route(
                &description,
                schema_for_type::<RouterInput>(),
                |server, arguments, _progress| -> ToolFuture<'_> {
                    Box::pin(ready(backups::list(server, arguments)))
                },
            ),
            Self::BackupDiff => route(
                &description,
                schema_for_type::<DiffInput>(),
                |server, arguments, _progress| -> ToolFuture<'_> {
                    Box::pin(ready(backups::diff(server, arguments)))
                },
            ),
        }
    }
}

/// The configuration-state and backup tools.
pub(crate) fn descriptions() -> Vec<ToolDescription> {
    Tool::ALL.into_iter().map(Tool::description).collect()
}

/// Routes of the configuration-state and backup tools.
pub(crate) fn routes() -> Vec<ToolRoute<KccMcp>> {
    Tool::ALL.into_iter().map(Tool::route).collect()
}
