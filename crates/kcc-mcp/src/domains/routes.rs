//! Dynamic RMCP routes of the domain tools.

use rmcp::handler::server::router::tool::ToolRoute;

use super::{
    entware,
    inventory::{READ_TOOLS, WRITE_TOOLS},
    read::{ReadInput, read, read_ops},
    table::descriptions,
    write::dispatch::{schema, write},
};
use crate::{
    KccMcp,
    support::route::{ToolFuture, route, schema_with_ops},
};

/// Routes of every domain tool, matched to their registry descriptions.
pub(crate) fn routes() -> Vec<ToolRoute<KccMcp>> {
    let described = descriptions();
    let mut routes = Vec::new();
    for &(area, name, _toolset, _description) in READ_TOOLS {
        if let Some(description) = described.iter().find(|tool| tool.name == name) {
            routes.push(route(
                description,
                schema_with_ops::<ReadInput>(read_ops(area)),
                move |server, arguments, _progress| -> ToolFuture<'_> {
                    Box::pin(read(server, area, arguments))
                },
            ));
        }
    }
    for &(area, name, _toolset, _description) in WRITE_TOOLS {
        if let Some(description) = described.iter().find(|tool| tool.name == name) {
            routes.push(route(
                description,
                schema(area),
                move |server, arguments, progress| -> ToolFuture<'_> {
                    Box::pin(write(server, area, arguments, progress))
                },
            ));
        }
    }
    routes.extend(entware::routes());
    routes
}
