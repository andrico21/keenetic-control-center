//! Registry descriptions and dynamic routes of the preset tools.

use kcc_app::permissions::Permission;
use rmcp::handler::server::{common::schema_for_type, router::tool::ToolRoute};

use super::{
    apply::apply,
    capture::{CaptureInput, capture},
    manage::{DeleteInput, ListInput, delete, list},
    plan::ApplyInput,
};
use crate::{
    KccMcp,
    registry::definitions::ToolDescription,
    support::route::{ToolFuture, route},
};

/// The preset tools.
pub(crate) fn descriptions() -> Vec<ToolDescription> {
    let tool = |name, description, permission, hints| {
        ToolDescription::single(name, description, "presets", permission, hints)
    };
    vec![
        tool(
            "kcc_preset_list",
            "List settings presets or read one by id, secrets redacted",
            Permission::Read,
            (true, false, true),
        ),
        tool(
            "kcc_preset_capture",
            "Capture settings groups from a router or backup as a stored or transient preset",
            Permission::Migrate,
            (false, false, false),
        ),
        tool(
            "kcc_preset_delete",
            "Delete a stored preset or forget a transient one",
            Permission::Migrate,
            (false, false, true),
        ),
        tool(
            "kcc_preset_apply",
            "Plan (dry run) or apply a preset onto a router under the router safety timer",
            Permission::Migrate,
            (false, true, false),
        ),
    ]
}

/// Routes of the preset tools.
pub(crate) fn routes() -> Vec<ToolRoute<KccMcp>> {
    descriptions()
        .iter()
        .map(|description| match description.name {
            "kcc_preset_list" => route(
                description,
                schema_for_type::<ListInput>(),
                |server, arguments, _progress| -> ToolFuture<'_> {
                    Box::pin(list(server, arguments))
                },
            ),
            "kcc_preset_capture" => route(
                description,
                schema_for_type::<CaptureInput>(),
                |server, arguments, _progress| -> ToolFuture<'_> {
                    Box::pin(capture(server, arguments))
                },
            ),
            "kcc_preset_delete" => route(
                description,
                schema_for_type::<DeleteInput>(),
                |server, arguments, _progress| -> ToolFuture<'_> {
                    Box::pin(delete(server, arguments))
                },
            ),
            _ => route(
                description,
                schema_for_type::<ApplyInput>(),
                |server, arguments, progress| -> ToolFuture<'_> {
                    Box::pin(apply(server, arguments, progress))
                },
            ),
        })
        .collect()
}
