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
#[derive(Clone, Copy)]
enum Tool {
    /// `kcc_preset_list`.
    List,
    /// `kcc_preset_capture`.
    Capture,
    /// `kcc_preset_delete`.
    Delete,
    /// `kcc_preset_apply`.
    Apply,
}

impl Tool {
    /// Every tool, in registry order.
    const ALL: [Self; 4] = [Self::List, Self::Capture, Self::Delete, Self::Apply];

    /// The tool's registry description.
    const fn description(self) -> ToolDescription {
        let (name, description, permission, hints) = match self {
            Self::List => (
                "kcc_preset_list",
                "List settings presets or read one by id, secrets redacted",
                Permission::Read,
                (true, false, true),
            ),
            Self::Capture => (
                "kcc_preset_capture",
                "Capture settings groups from a router or backup as a stored or transient preset",
                Permission::Migrate,
                (false, false, false),
            ),
            Self::Delete => (
                "kcc_preset_delete",
                "Delete a stored preset or forget a transient one",
                Permission::Migrate,
                (false, false, true),
            ),
            Self::Apply => (
                "kcc_preset_apply",
                "Plan (dry run) or apply a preset onto a router under the router safety timer",
                Permission::Migrate,
                (false, true, false),
            ),
        };
        ToolDescription::single(name, description, "presets", permission, hints)
    }

    /// The tool's route: its schema and handler.
    fn route(self) -> ToolRoute<KccMcp> {
        let description = self.description();
        match self {
            Self::List => route(
                &description,
                schema_for_type::<ListInput>(),
                |server, arguments, _progress| -> ToolFuture<'_> {
                    Box::pin(list(server, arguments))
                },
            ),
            Self::Capture => route(
                &description,
                schema_for_type::<CaptureInput>(),
                |server, arguments, _progress| -> ToolFuture<'_> {
                    Box::pin(capture(server, arguments))
                },
            ),
            Self::Delete => route(
                &description,
                schema_for_type::<DeleteInput>(),
                |server, arguments, _progress| -> ToolFuture<'_> {
                    Box::pin(delete(server, arguments))
                },
            ),
            Self::Apply => route(
                &description,
                schema_for_type::<ApplyInput>(),
                |server, arguments, progress| -> ToolFuture<'_> {
                    Box::pin(apply(server, arguments, progress))
                },
            ),
        }
    }
}

/// The preset tools.
pub(crate) fn descriptions() -> Vec<ToolDescription> {
    Tool::ALL.into_iter().map(Tool::description).collect()
}

/// Routes of the preset tools.
pub(crate) fn routes() -> Vec<ToolRoute<KccMcp>> {
    Tool::ALL.into_iter().map(Tool::route).collect()
}
