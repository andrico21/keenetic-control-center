//! MCP API key and audit log commands.

use std::time::{SystemTime, UNIX_EPOCH};

use kcc_app::{
    api_keys::{ApiKeysDocument, create_api_key, expose_created_key},
    audit::{AuditError, verify_chain},
    permissions::Permission,
};
use kcc_i18n::keys;
use serde_json::json;

use super::{
    accounts::known_role,
    args_admin::{ApiKeyCommand, AuditCommand},
    context::Ctx,
    exit::{Exit, Failure, Outcome},
};

/// Runs an `apikey` command.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: changes write local state.
pub(crate) async fn api_key(ctx: &Ctx, command: ApiKeyCommand) -> Outcome {
    ctx.principal().require(Permission::ManageUsers)?;
    let services = ctx.services().await?;
    let out = ctx.out();
    match command {
        ApiKeyCommand::Create { name, role } => {
            known_role(ctx, &role)?;
            let created = create_api_key(ctx.state(), name.clone(), role.clone(), now())?;
            ctx.audit(
                &services,
                "cli.apikey_create",
                None,
                json!({ "name": name, "role": role }),
                "success",
            )
            .await;
            let key = expose_created_key(&created);
            let document = json!({ "name": name, "role": role, "key": key });
            let human = format!("{}\n{key}", out.tr(keys::CLI_KEY_ONCE, &[("name", &name)]));
            out.emit(&document, &human)
        }
        ApiKeyCommand::List => {
            let keys_document = ctx.state().read::<ApiKeysDocument>()?.unwrap_or_default();
            let rows = keys_document
                .keys
                .iter()
                .map(|key| {
                    vec![
                        key.name.clone(),
                        key.role.clone(),
                        key.created_at.to_string(),
                    ]
                })
                .collect::<Vec<_>>();
            let document = json!({ "keys": keys_document.keys.iter().map(|key| json!({ "name": key.name, "role": key.role, "created_at": key.created_at, "last_used_at": key.last_used_at })).collect::<Vec<_>>() });
            out.table(
                &document,
                &[
                    keys::CLI_COL_NAME,
                    keys::CLI_COL_ROLE,
                    keys::CLI_COL_CREATED,
                ],
                &rows,
            )
        }
        ApiKeyCommand::Revoke { name } => {
            let removed = ctx.state().update(|document: &mut ApiKeysDocument| {
                let before = document.keys.len();
                document.keys.retain(|key| key.name != name);
                document.keys.len() != before
            })?;
            if !removed {
                return Err(Failure::message(
                    Exit::Usage,
                    keys::CLI_NOT_FOUND,
                    &[("name", &name)],
                ));
            }
            ctx.audit(
                &services,
                "cli.apikey_revoke",
                None,
                json!({ "name": name }),
                "success",
            )
            .await;
            out.emit(
                &json!({ "name": name, "revoked": true }),
                &out.tr(keys::CLI_DELETED, &[("name", &name)]),
            )
        }
    }
}

/// Runs an `audit` command.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// cancel-safe: reads local files only.
pub(crate) fn audit(ctx: &Ctx, command: &AuditCommand) -> Outcome {
    let &AuditCommand::Verify = command;
    ctx.principal().require(Permission::ViewAudit)?;
    let out = ctx.out();
    match verify_chain(ctx.state().dir()) {
        Ok(entries) => {
            let count = entries.len().to_string();
            let anchor = entries
                .first()
                .map(|entry| entry.prev_hash.as_str())
                .unwrap_or_default();
            out.emit(
                &json!({ "valid": true, "entries": entries.len(), "anchor": anchor }),
                &out.tr(keys::CLI_AUDIT_VALID, &[("count", &count)]),
            )
        }
        Err(AuditError::Chain { seq }) => {
            out.emit(&json!({ "valid": false, "broken_seq": seq }), "")?;
            Err(Failure::message(
                Exit::Generic,
                keys::CLI_AUDIT_BROKEN,
                &[("value", &seq.to_string())],
            ))
        }
        Err(error) => Err(error.into()),
    }
}

/// Current Unix seconds.
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}
