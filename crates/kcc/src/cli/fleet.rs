//! Router profiles, identity, `show` and the command catalog.

use kcc_app::permissions::Permission;
use kcc_catalog::{HttpMethod, ValidationIssue};
use kcc_config::mask::mask_reply;
use kcc_i18n::keys;
use kcc_rci::{
    RciBody, RciPath,
    capabilities::{RouterInfo, SupportTier},
};
use serde_json::{Value, json};

use super::{
    args_fleet::CatalogCommand,
    context::{Ctx, Target},
    exit::{Detail, Exit, Failure, Outcome},
};

/// Prints model, firmware and support tier.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// cancel-safe: reads only.
pub(crate) async fn info(ctx: &Ctx) -> Outcome {
    let services = ctx.services().await?;
    let target = ctx.target(&services, &[Permission::Read]).await?;
    let info = target.info();
    let (model, firmware) = identity(info);
    let (tier, tier_key) = match info.support_tier() {
        SupportTier::HardwareVerified => ("hardware_verified", keys::CLI_TIER_HARDWARE),
        SupportTier::DocumentationBased => ("documentation_based", keys::CLI_TIER_DOCUMENTATION),
        SupportTier::Unsupported | _ => ("unsupported", keys::CLI_TIER_UNSUPPORTED),
    };
    let out = ctx.out();
    let hardware = info.version.hw_id.clone().unwrap_or_default();
    let document = json!({
        "router": target.id(),
        "model": model,
        "hardware_id": hardware,
        "firmware": firmware,
        "support_tier": tier,
        "components": info.components,
    });
    let human = [
        out.tr(
            keys::CLI_INFO_MODEL,
            &[("model", &model), ("name", &hardware)],
        ),
        out.tr(keys::CLI_INFO_FIRMWARE, &[("version", &firmware)]),
        out.tr(keys::CLI_INFO_TIER, &[("value", &out.tr(tier_key, &[]))]),
    ]
    .join("\n");
    out.emit(&document, &human)
}

/// Runs a catalog-validated `show` command.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// cancel-safe: reads only.
pub(crate) async fn show(ctx: &Ctx, words: &[String]) -> Outcome {
    let services = ctx.services().await?;
    let target = ctx.target(&services, &[Permission::Read]).await?;
    let path = format!("show {}", words.join(" "));
    drop(
        target
            .router()
            .catalog
            .validate(&path, HttpMethod::Get, &json!({}))
            .map_err(|issues| Failure::new(Exit::Validation, Detail::Issues(issues)))?,
    );
    let segments = path.split_whitespace().collect::<Vec<_>>();
    let resource = RciPath::from_segments(&segments).map_err(|_error| {
        Failure::message(
            Exit::Validation,
            keys::WEB_EXPLORER_ISSUE_SEGMENT,
            &[("path", &path)],
        )
    })?;
    let body = target.router().client.show(&resource, &json!({})).await?;
    print_body(ctx, &target, body)
}

/// Runs a catalog command.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// cancel-safe: reads only.
pub(crate) async fn catalog(ctx: &Ctx, command: CatalogCommand) -> Outcome {
    let services = ctx.services().await?;
    let target = ctx.target(&services, &[Permission::Read]).await?;
    let catalog = &target.router().catalog;
    let out = ctx.out();
    match command {
        CatalogCommand::Search { query, limit } => {
            let results = catalog.search(&query.join(" "), usize::from(limit));
            let paths = results
                .iter()
                .map(|result| result.command.path.clone())
                .collect::<Vec<_>>();
            let document = json!({ "results": results.iter().map(|result| json!({ "path": result.command.path, "score": result.score })).collect::<Vec<_>>() });
            out.emit(&document, &paths.join("\n"))
        }
        CatalogCommand::Describe { path } => {
            let joined = path.join(" ");
            let schema = catalog.to_json_schema(&joined).ok_or_else(|| {
                Failure::new(
                    Exit::Validation,
                    Detail::Issues(vec![ValidationIssue::UnknownPath {
                        path: joined.clone(),
                    }]),
                )
            })?;
            let document = json!({ "path": joined, "schema": schema });
            out.emit(&document, &serde_json::to_string_pretty(&document)?)
        }
    }
}

/// Prints a router answer of `target`: JSON as JSON, text as text, its secrets redacted
/// unless the principal may see them ([`mask_unless_revealed`]).
///
/// # Errors
///
/// Returns the command's failure with its exit code.
pub(crate) fn print_body(ctx: &Ctx, target: &Target, body: RciBody) -> Outcome {
    let mut value = body_value(body);
    mask_unless_revealed(ctx, target, &mut value);
    let human = match &value {
        Value::String(text) => text.clone(),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::Array(_) | Value::Object(_) => {
            serde_json::to_string_pretty(&value)?
        }
    };
    ctx.out().emit(&value, &human)
}

/// Redacts every secret of `reply`, a router answer of `target` ([`mask_reply`]), unless
/// the principal holds `RevealSecrets` on that router.
pub(crate) fn mask_unless_revealed(ctx: &Ctx, target: &Target, reply: &mut Value) {
    if ctx
        .principal()
        .authorize(&[Permission::RevealSecrets], &[target.id()])
        .is_err()
    {
        mask_reply(reply, "<redacted>");
    }
}

/// A router answer as one JSON value.
pub(crate) fn body_value(body: RciBody) -> Value {
    match body {
        RciBody::Json(response) => response.value,
        RciBody::Text(text) => Value::String(text),
        _ => Value::Null,
    }
}

/// Model and firmware text of a detected router.
pub(crate) fn identity(info: &RouterInfo) -> (String, String) {
    let model = info
        .version
        .model
        .clone()
        .or_else(|| info.version.hw_id.clone())
        .unwrap_or_default();
    let firmware = info
        .version
        .title
        .clone()
        .or_else(|| info.firmware.map(|version| version.to_string()))
        .unwrap_or_default();
    (model, firmware)
}
