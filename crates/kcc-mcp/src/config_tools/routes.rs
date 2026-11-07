//! Registry descriptions and dynamic routes of the backup tools.

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
pub(crate) fn descriptions() -> Vec<ToolDescription> {
    vec![
        ToolDescription::single(
            "kcc_config_state",
            "Read unsaved state, fail-safe state, and the last change",
            "core",
            Permission::Read,
            (true, false, true),
        ),
        ToolDescription::single(
            "kcc_config_save",
            "Explicitly save the router running configuration",
            "core",
            Permission::Save,
            (false, false, true),
        ),
        ToolDescription::single(
            "kcc_backup_create",
            "Store the router's startup configuration as an encrypted backup",
            "system-admin",
            Permission::Write,
            (false, false, false),
        ),
        ToolDescription::single(
            "kcc_backup_list",
            "List the router's encrypted backups",
            "system-admin",
            Permission::Read,
            (true, false, true),
        ),
        ToolDescription::single(
            "kcc_backup_diff",
            "Diff two backups with secrets redacted",
            "system-admin",
            Permission::Read,
            (true, false, true),
        ),
    ]
}

/// Routes of the configuration-state and backup tools.
pub(crate) fn routes() -> Vec<ToolRoute<KccMcp>> {
    let described = descriptions();
    let mut routes = Vec::new();
    for description in &described {
        let entry = match description.name {
            "kcc_config_state" => route(
                description,
                schema_for_type::<RouterInput>(),
                |server, arguments, _progress| -> ToolFuture<'_> {
                    Box::pin(state::config_state(server, arguments))
                },
            ),
            "kcc_config_save" => route(
                description,
                schema_for_type::<RouterInput>(),
                |server, arguments, _progress| -> ToolFuture<'_> {
                    Box::pin(state::config_save(server, arguments))
                },
            ),
            "kcc_backup_create" => route(
                description,
                schema_for_type::<RouterInput>(),
                |server, arguments, _progress| -> ToolFuture<'_> {
                    Box::pin(backups::create(server, arguments))
                },
            ),
            "kcc_backup_list" => route(
                description,
                schema_for_type::<RouterInput>(),
                |server, arguments, _progress| -> ToolFuture<'_> {
                    Box::pin(core::future::ready(backups::list(server, arguments)))
                },
            ),
            _ => route(
                description,
                schema_for_type::<DiffInput>(),
                |server, arguments, _progress| -> ToolFuture<'_> {
                    Box::pin(core::future::ready(backups::diff(server, arguments)))
                },
            ),
        };
        routes.push(entry);
    }
    routes
}
