//! `kcc mcp clients`: the MCP clients registered for kcc sign-in, and deleting one with
//! its connections.

use kcc_app::{
    accounts::{Clock as _, SystemClock},
    mcp_auth::{
        clients::{ClientsDocument, MAX_CLIENTS},
        connections::{delete_client, live_grants, redirect_hosts, shown},
    },
};
use kcc_i18n::keys;
use serde_json::json;

use super::{
    args_mcp::McpClientsCommand,
    context::Ctx,
    exit::{Exit, Failure, Outcome},
    mcp_connections::{confirm, grant_ids, id_shaped},
    output::render_table,
};

/// Runs a `kcc mcp clients` command.
///
/// # Errors
///
/// Returns the command's failure with its exit code: 4 for a malformed client id, 10
/// without the confirmation, 2 for an unknown client.
// NOT cancel-safe: deleting writes local state and appends an audit entry.
pub(crate) async fn clients(ctx: &Ctx, command: McpClientsCommand) -> Outcome {
    match command {
        McpClientsCommand::List => list(ctx),
        McpClientsCommand::Delete { id } => {
            id_shaped(&id, keys::CLI_MCP_CLIENT_ID_INVALID)?;
            let services = ctx.services().await?;
            confirm(ctx, &services, &id).await?;
            let Some((client, revoked)) = delete_client(ctx.state(), &id)? else {
                return Err(Failure::message(
                    Exit::Usage,
                    keys::CLI_MCP_CLIENT_UNKNOWN,
                    &[("id", &id)],
                ));
            };
            let ids = grant_ids(&revoked);
            let params = json!({ "client": client.id(), "grants": ids });
            ctx.audit(&services, "cli.mcp_client_delete", None, params, "success")
                .await;
            let out = ctx.out();
            let count = revoked.len().to_string();
            out.emit(
                &json!({ "client": client.id(), "deleted": true, "revoked": ids }),
                &out.tr(
                    keys::CLI_MCP_CLIENT_DELETED,
                    &[("id", client.id()), ("count", &count)],
                ),
            )
        }
    }
}

/// Lists the registered clients with their redirect URIs and live connections, and how
/// many of the [`MAX_CLIENTS`] places are taken.
///
/// # Errors
///
/// A state read failure.
fn list(ctx: &Ctx) -> Outcome {
    let out = ctx.out();
    let now = SystemClock::default().unix_seconds();
    let document = ctx.state().read::<ClientsDocument>()?.unwrap_or_default();
    let grants = live_grants(ctx.state(), now)?;
    let mut rows = Vec::new();
    let mut entries = Vec::new();
    for client in document.clients() {
        let held = grants
            .iter()
            .filter(|grant| grant.client() == client.id())
            .count();
        let name = client.name().map(shown);
        let uris = client
            .redirect_uris()
            .iter()
            .map(|uri| shown(uri))
            .collect::<Vec<_>>();
        entries.push(json!({
            "id": client.id(),
            "name": name,
            "redirect_uris": uris,
            "registered_at": client.registered_at(),
            "last_grant_at": client.last_grant_at(),
            "pre_registered": client.is_pre_registered(),
            "connections": held,
        }));
        let kind = if client.is_pre_registered() {
            keys::CLI_MCP_PRE_REGISTERED
        } else {
            keys::CLI_MCP_DYNAMIC
        };
        rows.push(vec![
            client.id().to_owned(),
            name.unwrap_or_default(),
            redirect_hosts(client).join(" "),
            out.tr(kind, &[]),
            client.registered_at().to_string(),
            held.to_string(),
        ]);
    }
    let registered = document.clients().len();
    let value = json!({ "clients": entries, "registered": registered, "limit": MAX_CLIENTS });
    let count = out.tr(
        keys::CLI_MCP_CLIENTS_COUNT,
        &[
            ("count", &registered.to_string()),
            ("max", &MAX_CLIENTS.to_string()),
        ],
    );
    if rows.is_empty() {
        let none = out.tr(keys::CLI_MCP_CLIENTS_NONE, &[]);
        return out.emit(&value, &format!("{none}\n{count}"));
    }
    let headers = [
        keys::CLI_MCP_COL_ID,
        keys::CLI_MCP_COL_NAME,
        keys::CLI_MCP_COL_REDIRECT,
        keys::CLI_MCP_COL_KIND,
        keys::CLI_MCP_COL_REGISTERED,
        keys::CLI_MCP_COL_CONNECTIONS,
    ]
    .map(|key| out.tr(key, &[]));
    out.emit(
        &value,
        &format!("{}\n{count}", render_table(&headers, &rows)),
    )
}
