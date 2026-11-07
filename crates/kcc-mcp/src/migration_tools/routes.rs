//! Registry descriptions and dynamic routes of the migration tools.

use kcc_app::permissions::Permission;
use rmcp::handler::server::{common::schema_for_type, router::tool::ToolRoute};

use super::{
    apply::{ApplyInput, apply},
    finish::{FinishInput, ReportInput, finish, report},
    plan::{InventoryInput, PlanInput, inventory, plan},
};
use crate::{
    KccMcp,
    registry::definitions::ToolDescription,
    support::route::{ToolFuture, route},
};

/// The migration tools.
pub(crate) fn descriptions() -> Vec<ToolDescription> {
    let tool = |name, description, hints| {
        ToolDescription::single(name, description, "migration", Permission::Migrate, hints)
    };
    vec![
        tool(
            "kcc_migration_inventory",
            "Read a target router's migration inventory",
            (true, false, true),
        ),
        tool(
            "kcc_migration_plan",
            "Plan migrating a source router's configuration onto a target",
            (true, false, false),
        ),
        tool(
            "kcc_migration_apply",
            "Apply a reviewed migration plan under the router safety timer",
            (false, true, false),
        ),
        tool(
            "kcc_migration_finish",
            "Commit or roll back an applied migration",
            (false, true, false),
        ),
        tool(
            "kcc_migration_report",
            "Read a migration's plan counts, items, and apply outcome",
            (true, false, true),
        ),
    ]
}

/// Routes of the migration tools.
pub(crate) fn routes() -> Vec<ToolRoute<KccMcp>> {
    descriptions()
        .iter()
        .map(|description| match description.name {
            "kcc_migration_inventory" => route(
                description,
                schema_for_type::<InventoryInput>(),
                |server, arguments, _progress| -> ToolFuture<'_> {
                    Box::pin(inventory(server, arguments))
                },
            ),
            "kcc_migration_plan" => route(
                description,
                schema_for_type::<PlanInput>(),
                |server, arguments, _progress| -> ToolFuture<'_> {
                    Box::pin(plan(server, arguments))
                },
            ),
            "kcc_migration_apply" => route(
                description,
                schema_for_type::<ApplyInput>(),
                |server, arguments, progress| -> ToolFuture<'_> {
                    Box::pin(apply(server, arguments, progress))
                },
            ),
            "kcc_migration_finish" => route(
                description,
                schema_for_type::<FinishInput>(),
                |server, arguments, _progress| -> ToolFuture<'_> {
                    Box::pin(finish(server, arguments))
                },
            ),
            _ => route(
                description,
                schema_for_type::<ReportInput>(),
                |server, arguments, _progress| -> ToolFuture<'_> {
                    Box::pin(report(server, arguments))
                },
            ),
        })
        .collect()
}
