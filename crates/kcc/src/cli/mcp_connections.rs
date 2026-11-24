//! `kcc mcp connections`: the live connections of MCP clients signed in with kcc
//! accounts, and revoking one or every one of an account.
//!
//! A connection is a grant: no token or hash is ever printed. Revoking needs
//! `--confirm-destructive` naming what goes (the grant id or the account), or that name
//! typed on a terminal; `--yes` never stands in. A running `kcc serve` refuses the
//! revoked grant at its very next MCP call.

use std::io::{self, BufRead as _, IsTerminal as _, Write as _};

use kcc_app::{
    accounts::{Clock as _, SystemClock},
    audit::Attempt,
    mcp_auth::{
        clients::ClientsDocument,
        connections::{live_grants, redirect_hosts, revoke, revoke_account, shown},
        grants::Grant,
    },
};
use kcc_i18n::{bundle::MessageKey, keys};
use serde_json::{Value, json};

use super::{
    args_mcp::McpConnectionsCommand,
    context::{Ctx, Services},
    exit::{Exit, Failure, Outcome},
};

/// Runs a `kcc mcp connections` command.
///
/// # Errors
///
/// Returns the command's failure with its exit code: 4 for a malformed grant id, 10
/// without the confirmation, 2 when there is nothing to revoke.
// NOT cancel-safe: revoking writes local state and appends an audit entry.
pub(crate) async fn connections(ctx: &Ctx, command: McpConnectionsCommand) -> Outcome {
    match command {
        McpConnectionsCommand::List => list(ctx),
        McpConnectionsCommand::Revoke { grant_id } => {
            id_shaped(&grant_id, keys::CLI_MCP_GRANT_ID_INVALID)?;
            let services = ctx.services().await?;
            confirm(ctx, &services, &grant_id).await?;
            let Some(grant) = revoke(ctx.state(), &grant_id)? else {
                return Err(Failure::message(
                    Exit::Usage,
                    keys::CLI_MCP_GRANT_UNKNOWN,
                    &[("id", &grant_id)],
                ));
            };
            let params = json!({
                "account": grant.account(),
                "client": grant.client(),
                "grants": [grant.id()],
            });
            ctx.audit(&services, "cli.mcp_grant_revoke", None, params, "success")
                .await;
            let out = ctx.out();
            out.emit(
                &json!({ "grant": grant.id(), "account": grant.account(), "revoked": true }),
                &out.tr(keys::CLI_MCP_REVOKED, &[("id", grant.id())]),
            )
        }
        McpConnectionsCommand::RevokeAccount { user } => {
            let services = ctx.services().await?;
            confirm(ctx, &services, &user).await?;
            let revoked = revoke_account(ctx.state(), &user)?;
            if revoked.is_empty() {
                return Err(Failure::message(
                    Exit::Usage,
                    keys::CLI_MCP_ACCOUNT_NO_GRANTS,
                    &[("name", &user)],
                ));
            }
            let ids = revoked.iter().map(Grant::id).collect::<Vec<_>>();
            let params = json!({ "account": user, "grants": ids });
            ctx.audit(&services, "cli.mcp_grant_revoke", None, params, "success")
                .await;
            let out = ctx.out();
            let count = ids.len().to_string();
            out.emit(
                &json!({ "account": user, "revoked": ids }),
                &out.tr(
                    keys::CLI_MCP_REVOKED_ACCOUNT,
                    &[("name", &user), ("count", &count)],
                ),
            )
        }
    }
}

/// Lists the live connections with their client's name and redirect hosts.
///
/// # Errors
///
/// A state read failure.
fn list(ctx: &Ctx) -> Outcome {
    let out = ctx.out();
    let now = SystemClock::default().unix_seconds();
    let grants = live_grants(ctx.state(), now)?;
    let clients = ctx.state().read::<ClientsDocument>()?.unwrap_or_default();
    let mut rows = Vec::new();
    let mut entries = Vec::new();
    for grant in &grants {
        let client = clients.client(grant.client());
        let name = client.and_then(|found| found.name()).map(shown);
        let hosts = client.map_or_default(redirect_hosts);
        entries.push(json!({
            "grant": grant.id(),
            "account": grant.account(),
            "client": grant.client(),
            "client_name": name,
            "redirect_hosts": hosts,
            "created_at": grant.created_at(),
            "last_used_at": grant.last_used_at(),
            "refresh_expires_at": grant.refresh_expires_at(),
            "resource": grant.resource(),
        }));
        rows.push(vec![
            grant.id().to_owned(),
            grant.account().to_owned(),
            name.unwrap_or_else(|| grant.client().to_owned()),
            hosts.join(" "),
            grant.created_at().to_string(),
            grant.last_used_at().to_string(),
            grant.resource().to_owned(),
        ]);
    }
    let document = json!({ "connections": entries });
    if rows.is_empty() && !out.json() {
        return out.emit(&document, &out.tr(keys::CLI_MCP_CONNECTIONS_NONE, &[]));
    }
    out.table(
        &document,
        &[
            keys::CLI_MCP_COL_GRANT,
            keys::CLI_MCP_COL_ACCOUNT,
            keys::CLI_MCP_COL_CLIENT,
            keys::CLI_MCP_COL_REDIRECT,
            keys::CLI_MCP_COL_CREATED,
            keys::CLI_MCP_COL_LAST_USED,
            keys::CLI_MCP_COL_RESOURCE,
        ],
        &rows,
    )
}

/// Refuses `id` unless it is 64 lowercase hex digits, the shape of every grant and client
/// id, with `invalid` (exit 4; the value is not repeated).
///
/// # Errors
///
/// The validation failure.
pub(super) fn id_shaped(id: &str, invalid: MessageKey) -> Outcome {
    let shaped = id.len() == 64
        && id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if shaped {
        Ok(())
    } else {
        Err(Failure::message(Exit::Validation, invalid, &[]))
    }
}

/// Requires `--confirm-destructive <object>`, or `object` typed on a terminal.
///
/// A missing or wrong confirmation is audited as `cli.refused` (`confirm_required`) and refused
/// (exit 10). `--yes` never stands in for it.
///
/// # Errors
///
/// The policy refusal, or a terminal I/O failure.
// NOT cancel-safe: the refusal audit may append after cancellation.
pub(super) async fn confirm(ctx: &Ctx, services: &Services, object: &str) -> Outcome {
    let confirmed = ctx
        .globals()
        .confirm_destructive()
        .map_or_else(|| typed(ctx, object), |given| Ok(given == object));
    match confirmed {
        Ok(true) => Ok(()),
        Ok(false) => {
            let reason = Attempt::Refused {
                reason: "confirm_required",
            };
            ctx.attempt(services, "cli.refused", None, reason).await;
            Err(Failure::message(
                Exit::Policy,
                keys::CLI_MCP_CONFIRM_MISSING,
                &[("name", object)],
            ))
        }
        Err(failure) => Err(failure),
    }
}

/// Whether `object` was typed back on the terminal; `false` without a terminal.
///
/// # Errors
///
/// A terminal I/O failure.
fn typed(ctx: &Ctx, object: &str) -> Outcome<bool> {
    let stdin = io::stdin();
    if !stdin.is_terminal() {
        return Ok(false);
    }
    let out = ctx.out();
    let mut stderr = io::stderr().lock();
    write!(
        stderr,
        "{} ",
        out.tr(keys::CLI_MCP_CONFIRM_TYPE, &[("name", object)])
    )?;
    stderr.flush()?;
    let mut line = String::new();
    let _: usize = stdin.lock().read_line(&mut line)?;
    Ok(line.trim() == object)
}

/// The JSON of a client's revoked grants: their ids.
pub(super) fn grant_ids(grants: &[Grant]) -> Value {
    Value::from(grants.iter().map(Grant::id).collect::<Vec<_>>())
}
