//! `kcc notify token`: seals the bot token, or removes it.
//!
//! The token comes from a file, `KCC_PASSWORD` or a hidden prompt, never from an argument
//! value; it is never printed and never audited: the audit records only that the
//! credential changed or was cleared.

use std::path::Path;

use kcc_app::notify_store::{NotifyError, token::NotifySecrets};
use kcc_i18n::keys;
use serde_json::json;

use super::{audit, view};
use crate::cli::{
    context::Ctx,
    exit::{Exit, Failure, Outcome},
    secret::read_secret,
};

/// Seals the token from `file` (else `--password-file`, `KCC_PASSWORD` or a prompt), or
/// removes it when `clear`.
///
/// # Errors
///
/// Returns secret input, token shape, key, state or output failures.
// NOT cancel-safe: the token may be stored without its audit entry.
pub(super) async fn run(ctx: &Ctx, file: Option<&Path>, clear: bool) -> Outcome {
    if clear {
        let services = ctx.services().await?;
        NotifySecrets::clear(ctx.state()).map_err(|error| stored(&error))?;
        let params = json!({ "credential_cleared": true });
        audit(ctx, &services, ("cli.notify_token", params), "success").await;
        return view::show(ctx, Some(keys::CLI_NOTIFY_TOKEN_CLEARED));
    }
    let source = file.or_else(|| ctx.globals().password_file());
    let token = read_secret(source, &ctx.out().tr(keys::CLI_NOTIFY_TOKEN_PROMPT, &[]))?;
    let services = ctx.services().await?;
    match NotifySecrets::set_token(ctx.state(), services.key(), &token) {
        Ok(()) => {}
        Err(NotifyError::Invalid { field: _ }) => {
            return Err(Failure::message(
                Exit::Usage,
                keys::CLI_NOTIFY_TOKEN_INVALID,
                &[],
            ));
        }
        Err(error) => return Err(stored(&error)),
    }
    let params = json!({ "credential_changed": true });
    audit(ctx, &services, ("cli.notify_token", params), "success").await;
    view::show(ctx, Some(keys::CLI_NOTIFY_TOKEN_SAVED))
}

/// The failure of a token that could not be stored or removed; the error never carries
/// the token.
pub(super) fn stored(error: &NotifyError) -> Failure {
    Failure::text(Exit::Generic, error)
}
