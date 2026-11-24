//! `kcc mcp settings show` and the dispatch of the other `kcc mcp` commands.
//!
//! Every command needs `ManageMcp` from the `[cli] role` and is refused before it reads or
//! changes anything without it.

use kcc_app::{
    mcp_settings::{EnvOverrides, McpBase, Source, keys::KeyPath},
    permissions::Permission,
};
use kcc_i18n::{bundle::MessageKey, keys};
use serde_json::{Value, json};

use super::{
    args_mcp::{McpCommand, McpSettingsCommand},
    context::{Ctx, load_config_reporting},
    exit::{Exit, Failure, Outcome},
    mcp_clients, mcp_connections,
};

/// Runs one `kcc mcp` command other than `stdio`, which `kcc serve`'s sibling runs.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: the connection and client commands change local state.
pub(crate) async fn run(ctx: &Ctx, command: McpCommand) -> Outcome {
    ctx.principal().require(Permission::ManageMcp)?;
    match command {
        McpCommand::Settings(McpSettingsCommand::Show) => settings(ctx),
        McpCommand::Connections(sub) => Box::pin(mcp_connections::connections(ctx, sub)).await,
        McpCommand::Clients(sub) => Box::pin(mcp_clients::clients(ctx, sub)).await,
        McpCommand::Stdio => Err(Failure::text(
            Exit::Usage,
            "`kcc mcp stdio` runs the transport; it is not a settings command",
        )),
    }
}

/// `kcc mcp settings show`: every Web-managed key's effective value and its source, the
/// way `kcc serve` would resolve it now; `[mcp] locked` as listed in kcc.toml.
///
/// # Errors
///
/// A configuration, state or settings failure.
fn settings(ctx: &Ctx) -> Outcome {
    let out = ctx.out();
    let (config, reports) = load_config_reporting(ctx.globals().config())?;
    let base = McpBase::new(&config, &EnvOverrides::from_reports(&reports));
    let effective = base
        .effective(ctx.state())
        .map_err(|error| Failure::text(Exit::Generic, &error))?;
    let values = serde_json::to_value(effective.values())?;
    let rows = KeyPath::ALL
        .iter()
        .map(|key| {
            let value = key
                .as_str()
                .split('.')
                .try_fold(&values, |node, part| node.get(part))
                .cloned()
                .unwrap_or(Value::Null);
            (*key, value, effective.source(*key))
        })
        .collect::<Vec<_>>();
    let document = json!({
        "settings": rows
            .iter()
            .map(|(key, value, source)| json!({
                "key": key.as_str(),
                "value": value,
                "source": source_name(*source),
            }))
            .collect::<Vec<_>>(),
        "locked": config.mcp.locked,
    });
    let unset = out.tr(keys::CLI_MCP_NOT_SET, &[]);
    let table = rows
        .iter()
        .map(|(key, value, source)| {
            let text = match value {
                Value::Null => unset.clone(),
                Value::String(text) => text.clone(),
                other
                @ (Value::Bool(_) | Value::Number(_) | Value::Array(_) | Value::Object(_)) => {
                    other.to_string()
                }
            };
            vec![
                key.as_str().to_owned(),
                text,
                out.tr(source_label(*source), &[]),
            ]
        })
        .collect::<Vec<_>>();
    out.table(
        &document,
        &[
            keys::CLI_MCP_COL_KEY,
            keys::CLI_MCP_COL_VALUE,
            keys::CLI_MCP_COL_SOURCE,
        ],
        &table,
    )
}

/// The stable name of `source` in `--json` output.
const fn source_name(source: Source) -> &'static str {
    match source {
        Source::Env => "env",
        Source::Locked => "locked",
        Source::State => "state",
        Source::Toml => "toml",
        Source::Default | _ => "default",
    }
}

/// The localized word for `source`.
const fn source_label(source: Source) -> MessageKey {
    match source {
        Source::Env => keys::CLI_MCP_SOURCE_ENV,
        Source::Locked => keys::CLI_MCP_SOURCE_LOCKED,
        Source::State => keys::CLI_MCP_SOURCE_STATE,
        Source::Toml => keys::CLI_MCP_SOURCE_TOML,
        Source::Default | _ => keys::CLI_MCP_SOURCE_DEFAULT,
    }
}
