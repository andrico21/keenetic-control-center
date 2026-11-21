//! MCP API key and audit log commands.

use kcc_app::{
    accounts::{Clock as _, SystemClock},
    api_keys::{ApiKeyError, ApiKeysDocument, create_api_key, expires_after, expose_created_key},
    audit::{AuditError, verify_chain},
    permissions::{Permission, assignment::GrantError},
};
use kcc_i18n::keys;
use serde_json::json;

use super::{
    accounts::refused_grant,
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
        ApiKeyCommand::Create {
            name,
            role,
            expires_in,
        } => {
            let actor = ctx.principal().authority()?;
            let now = SystemClock::default().unix_seconds();
            let expires_at = expires_in
                .map(|lifetime| expires_after(now, &lifetime))
                .transpose()?;
            let created = match create_api_key(
                ctx.state(),
                &actor,
                name.clone(),
                role.clone(),
                now,
                expires_at,
            ) {
                Err(ApiKeyError::Grant(GrantError::Forbidden)) => {
                    let params = json!({ "name": name, "role": role });
                    return Err(refused_grant(ctx, &services, "cli.apikey_create", params).await);
                }
                result => result?,
            };
            let params = expires_at.map_or_else(
                || json!({ "name": name, "role": role }),
                |at| json!({ "name": name, "role": role, "expires_at": at }),
            );
            ctx.audit(&services, "cli.apikey_create", None, params, "success")
                .await;
            let key = expose_created_key(&created);
            let document =
                json!({ "name": name, "role": role, "key": key, "expires_at": expires_at });
            let human = format!("{}\n{key}", out.tr(keys::CLI_KEY_ONCE, &[("name", &name)]));
            out.emit(&document, &human)
        }
        ApiKeyCommand::List => list(ctx),
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

/// Lists the keys with their expiry; an expired key is marked.
///
/// # Errors
///
/// A state read failure.
fn list(ctx: &Ctx) -> Outcome {
    let out = ctx.out();
    let keys_document = ctx.state().read::<ApiKeysDocument>()?.unwrap_or_default();
    let now = SystemClock::default().unix_seconds();
    let expired_word = out.tr(keys::CLI_KEY_EXPIRED, &[]);
    let rows = keys_document
        .keys
        .iter()
        .map(|key| {
            let expires = key.expires_at.map_or_default(|at| {
                if key.is_expired(now) {
                    format!("{at} ({expired_word})")
                } else {
                    at.to_string()
                }
            });
            vec![
                key.name.clone(),
                key.role.clone(),
                key.created_at.to_string(),
                expires,
            ]
        })
        .collect::<Vec<_>>();
    let document = json!({ "keys": keys_document.keys.iter().map(|key| json!({ "name": key.name, "role": key.role, "created_at": key.created_at, "last_used_at": key.last_used_at, "expires_at": key.expires_at, "expired": key.is_expired(now) })).collect::<Vec<_>>() });
    out.table(
        &document,
        &[
            keys::CLI_COL_NAME,
            keys::CLI_COL_ROLE,
            keys::CLI_COL_CREATED,
            keys::CLI_COL_EXPIRES,
        ],
        &rows,
    )
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
                .map_or_default(|entry| entry.prev_hash.as_str());
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
