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
#[derive(Clone, Copy)]
enum Tool {
    /// `kcc_migration_inventory`.
    Inventory,
    /// `kcc_migration_plan`.
    Plan,
    /// `kcc_migration_apply`.
    Apply,
    /// `kcc_migration_finish`.
    Finish,
    /// `kcc_migration_report`.
    Report,
}

impl Tool {
    /// Every tool, in registry order.
    const ALL: [Self; 5] = [
        Self::Inventory,
        Self::Plan,
        Self::Apply,
        Self::Finish,
        Self::Report,
    ];

    /// The tool's registry description.
    const fn description(self) -> ToolDescription {
        let (name, description, permission, hints) = match self {
            Self::Inventory => (
                "kcc_migration_inventory",
                "Read a target router's migration inventory",
                Permission::Migrate,
                (true, false, true),
            ),
            Self::Plan => (
                "kcc_migration_plan",
                "Plan migrating a source router's configuration onto a target",
                Permission::Migrate,
                (true, false, false),
            ),
            Self::Apply => (
                "kcc_migration_apply",
                "Apply a reviewed migration plan under the router safety timer",
                Permission::Migrate,
                (false, true, false),
            ),
            Self::Finish => (
                "kcc_migration_finish",
                "Commit or roll back an applied migration",
                Permission::Migrate,
                (false, true, false),
            ),
            Self::Report => (
                "kcc_migration_report",
                "Read a migration's plan counts, items, and apply outcome",
                Permission::Migrate,
                (true, false, true),
            ),
        };
        ToolDescription::single(name, description, "migration", permission, hints)
    }

    /// The tool's route: its schema and handler.
    fn route(self) -> ToolRoute<KccMcp> {
        let description = self.description();
        match self {
            Self::Inventory => route(
                &description,
                schema_for_type::<InventoryInput>(),
                |server, arguments, _progress| -> ToolFuture<'_> {
                    Box::pin(inventory(server, arguments))
                },
            ),
            Self::Plan => route(
                &description,
                schema_for_type::<PlanInput>(),
                |server, arguments, _progress| -> ToolFuture<'_> {
                    Box::pin(plan(server, arguments))
                },
            ),
            Self::Apply => route(
                &description,
                schema_for_type::<ApplyInput>(),
                |server, arguments, progress| -> ToolFuture<'_> {
                    Box::pin(apply(server, arguments, progress))
                },
            ),
            Self::Finish => route(
                &description,
                schema_for_type::<FinishInput>(),
                |server, arguments, _progress| -> ToolFuture<'_> {
                    Box::pin(finish(server, arguments))
                },
            ),
            Self::Report => route(
                &description,
                schema_for_type::<ReportInput>(),
                |server, arguments, _progress| -> ToolFuture<'_> {
                    Box::pin(report(server, arguments))
                },
            ),
        }
    }
}

/// The migration tools.
pub(crate) fn descriptions() -> Vec<ToolDescription> {
    Tool::ALL.into_iter().map(Tool::description).collect()
}

/// Routes of the migration tools.
pub(crate) fn routes() -> Vec<ToolRoute<KccMcp>> {
    Tool::ALL.into_iter().map(Tool::route).collect()
}
