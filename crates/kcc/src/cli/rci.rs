//! Catalog-validated raw RCI requests.

use std::{
    fs,
    io::{self, Read as _},
};

use kcc_app::{
    permissions::Permission,
    workflow::{BatchChangeRequest, BatchItem, DeleteRequest},
};
use kcc_catalog::{Catalog, HttpMethod, Risk};
use kcc_i18n::keys;
use kcc_rci::{RciBody, RciError, RciPath, RciResponse};
use serde_json::{Map, Value, json};

use super::{
    args_fleet::RciCommand,
    change::{Gate, labelled, run as run_change},
    context::{Ctx, Services, Target},
    exit::{Detail, Exit, Failure, Outcome},
    fleet::{body_value, print_body},
};

/// Largest request body read from `--data`.
const MAX_BODY: u64 = 256 * 1024;

/// Most root objects in one batch.
const MAX_BATCH: usize = 50;

/// Runs an `rci` command.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: writes may apply before cancellation.
pub(crate) async fn run(ctx: &Ctx, command: RciCommand) -> Outcome {
    let services = ctx.services().await?;
    match command {
        RciCommand::Get { path, data } => {
            let target = ctx
                .target(&services, &[Permission::RawRci, Permission::Read])
                .await?;
            let value = data.as_deref().map_or_else(|| Ok(json!({})), read_data)?;
            let joined = path.join(" ");
            drop(validate(
                &target.router().catalog,
                &joined,
                HttpMethod::Get,
                &value,
            )?);
            let resource = RciPath::from_segments(&path).map_err(|_error| RciError::Validation)?;
            let body = if path.first().is_some_and(|word| word == "show") {
                target.router().client.show(&resource, &value).await?
            } else {
                target.router().client.get(&resource, &value).await?
            };
            print_body(ctx, body)
        }
        RciCommand::Delete { path, data } => {
            let target = ctx.target(&services, &[Permission::RawRci]).await?;
            let value = data.as_deref().map_or_else(|| Ok(json!({})), read_data)?;
            let joined = path.join(" ");
            let validated = validate(
                &target.router().catalog,
                &joined,
                HttpMethod::Delete,
                &value,
            )?;
            let gate = Gate::new(
                validated.risk.max(Risk::Destructive),
                Permission::RawRci,
                true,
            )
            .persisting(validated.persists_immediately);
            let document = run_change(ctx, &services, &target, gate, async |changes, _router| {
                let request = DeleteRequest::new(
                    joined,
                    path,
                    value,
                    Vec::new(),
                    Permission::RawRci,
                    json!({ "method": "DELETE" }),
                );
                let result = changes.apply_delete(request).await?;
                Ok(json!({ "applied": true, "unsaved": result.unsaved }))
            })
            .await?;
            ctx.out()
                .emit(&document, &ctx.out().tr(gate.applied(), &[]))
        }
        RciCommand::Post { path, data } => {
            let target = ctx.target(&services, &[Permission::RawRci]).await?;
            let value = read_data(&data)?;
            let items = if path.is_empty() {
                root_items(&target.router().catalog, value, false)?
            } else {
                let joined = path.join(" ");
                let validated =
                    validate(&target.router().catalog, &joined, HttpMethod::Post, &value)?;
                vec![BatchItem::new(nest(&path, value), validated)]
            };
            send(ctx, &services, &target, items).await
        }
        RciCommand::Batch { data } => {
            let target = ctx.target(&services, &[Permission::RawRci]).await?;
            let items = root_items(&target.router().catalog, read_data(&data)?, true)?;
            send(ctx, &services, &target, items).await
        }
    }
}

/// Sends validated root items: reads directly, changes through the workflow.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: writes may apply before cancellation.
async fn send(ctx: &Ctx, services: &Services, target: &Target, items: Vec<BatchItem>) -> Outcome {
    let risk = items
        .iter()
        .map(|item| item.validated.risk)
        .max()
        .unwrap_or(Risk::Read);
    if risk == Risk::Read {
        drop(
            ctx.principal()
                .authorize(&[Permission::Read], &[target.id()])?,
        );
        let values = items
            .iter()
            .map(|item| item.value.redacted().clone())
            .collect();
        let responses = target.router().client.batch(values).await?;
        return report(ctx, responses, false, &[]);
    }
    let persists =
        !items.is_empty() && items.iter().all(|item| item.validated.persists_immediately);
    let persisted_paths = items
        .iter()
        .flat_map(|item| item.validated.persisted_paths.iter().cloned())
        .collect::<Vec<_>>();
    let gate = Gate::new(risk, Permission::RawRci, true).persisting(persists);
    if !persists && !persisted_paths.is_empty() {
        ctx.out().note(&ctx.out().tr(
            keys::CLI_MIXED_PERSISTENCE,
            &[("paths", persisted_paths.join(", ").as_str())],
        ));
    }
    let mut responses = Vec::new();
    drop(
        run_change(ctx, services, target, gate, async |changes, _router| {
            let request = BatchChangeRequest::new(
                items,
                Vec::new(),
                Permission::RawRci,
                json!({ "method": "POST" }),
            );
            responses = changes.apply_batch(request).await?.responses;
            Ok(Value::Null)
        })
        .await?,
    );
    report(ctx, responses, persists, &persisted_paths)
}

/// Prints per-item results and whether the router persisted them at once; any failed
/// item makes the command partial (exit 7).
///
/// # Errors
///
/// Returns the command's failure with its exit code.
fn report(
    ctx: &Ctx,
    responses: Vec<Result<RciResponse, RciError>>,
    persists: bool,
    persisted_paths: &[String],
) -> Outcome {
    let failed = responses
        .iter()
        .filter(|response| response.is_err())
        .count();
    let items = responses
        .into_iter()
        .map(|response| match response {
            Ok(value) => json!({ "ok": true, "value": body_value(RciBody::Json(value)) }),
            Err(error) => json!({ "ok": false, "error": error.to_string() }),
        })
        .collect::<Vec<_>>();
    let mut document = labelled(json!({ "items": items }), persists);
    if !persists
        && !persisted_paths.is_empty()
        && let Value::Object(object) = &mut document
    {
        drop(object.insert("persisted_paths".to_owned(), json!(persisted_paths)));
    }
    ctx.out()
        .emit(&document, &serde_json::to_string_pretty(&document)?)?;
    if failed == 0 {
        Ok(())
    } else {
        Err(Failure::new(Exit::Partial, Detail::None))
    }
}

/// Validates one root object or a batch array against the catalog.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
fn root_items(catalog: &Catalog, value: Value, batch_only: bool) -> Outcome<Vec<BatchItem>> {
    let values = match value {
        Value::Array(values) => values,
        Value::Object(_) if !batch_only => vec![value],
        Value::Object(_) | Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {
            return Err(Failure::message(
                Exit::Validation,
                keys::WEB_EXPLORER_ISSUE_ROOT,
                &[],
            ));
        }
    };
    if values.is_empty() || values.len() > MAX_BATCH {
        return Err(Failure::message(
            Exit::Validation,
            keys::WEB_EXPLORER_ISSUE_BATCH,
            &[("count", &MAX_BATCH.to_string())],
        ));
    }
    values
        .into_iter()
        .map(|item| {
            let validated = validate(catalog, "", HttpMethod::Post, &item)?;
            Ok(BatchItem::new(item, validated))
        })
        .collect()
}

/// Validates one request against the router's catalog; nothing is sent on failure.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
fn validate(
    catalog: &Catalog,
    path: &str,
    method: HttpMethod,
    value: &Value,
) -> Outcome<kcc_catalog::ValidatedRequest> {
    catalog
        .validate(path, method, value)
        .map_err(|issues| Failure::new(Exit::Validation, Detail::Issues(issues)))
}

/// Nests `value` under the words of `path` as one root object.
fn nest(path: &[String], value: Value) -> Value {
    path.iter().rev().fold(value, |inner, word| {
        let mut object = Map::new();
        drop(object.insert(word.clone(), inner));
        Value::Object(object)
    })
}

/// Reads `--data`: `@file`, `-` for stdin, or inline JSON.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
fn read_data(source: &str) -> Outcome<Value> {
    let text = if source == "-" {
        let mut text = String::new();
        let _: usize = io::stdin().take(MAX_BODY).read_to_string(&mut text)?;
        text
    } else if let Some(path) = source.strip_prefix('@') {
        let mut text = String::new();
        let _: usize = fs::File::open(path)?
            .take(MAX_BODY)
            .read_to_string(&mut text)?;
        text
    } else {
        source.to_owned()
    };
    serde_json::from_str(&text).map_err(|error| {
        Failure::message(
            Exit::Validation,
            keys::WEB_EXPLORER_ISSUE_JSON,
            &[
                ("line", &error.line().to_string()),
                ("column", &error.column().to_string()),
            ],
        )
    })
}
