//! Catalog-validated raw RCI requests.

use std::{
    fs,
    io::{self, Read as _},
};

use kcc_app::{
    audit::receipt::AuditReceipt,
    permissions::Permission,
    workflow::{BatchChangeRequest, BatchItem, ChangeRequest},
};
use kcc_catalog::{Catalog, HttpMethod, Risk, ValidatedRequest};
use kcc_i18n::{bundle::MessageKey, keys};
use kcc_rci::{RciBody, RciError, RciPath, RciResponse};
use serde_json::{Map, Value, json};

use super::{
    args_fleet::RciCommand,
    change::{Gate, labelled, run_completed, run_headlined},
    context::{Ctx, Services, Target},
    exit::{Detail, Exit, Failure, Outcome},
    fleet::{body_value, mask_unless_revealed, print_body},
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
            print_body(ctx, &target, body)
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
            .persisting(validated.persists_immediately)
            .recovery(validated.contains_management());
            let (document, headline) =
                run_headlined(ctx, &services, &target, gate, async |changes, _router| {
                    let request = ChangeRequest::delete(
                        joined,
                        path,
                        value,
                        Vec::new(),
                        Permission::RawRci,
                        json!({ "method": "DELETE" }),
                    );
                    let result = changes.apply(request).await?;
                    Ok(json!({ "applied": true, "unsaved": result.unsaved }))
                })
                .await?;
            ctx.out().note(&ctx.out().tr(headline, &[]));
            ctx.out()
                .emit(&document, &serde_json::to_string_pretty(&document)?)
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
                vec![(BatchItem::new(nest(&path, value)), validated)]
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
async fn send(
    ctx: &Ctx,
    services: &Services,
    target: &Target,
    items: Vec<(BatchItem, ValidatedRequest)>,
) -> Outcome {
    let risk = items
        .iter()
        .map(|(_item, validated)| validated.risk)
        .max()
        .unwrap_or(Risk::Read);
    if risk == Risk::Read {
        return read_batch(ctx, target, &items).await;
    }
    let persists = items
        .iter()
        .any(|(_item, validated)| !validated.persisted_paths.is_empty())
        && items
            .iter()
            .all(|(_item, validated)| validated.ordinary_paths.is_empty());
    let persisted_paths = items
        .iter()
        .flat_map(|(_item, validated)| validated.persisted_paths.iter().cloned())
        .collect::<Vec<_>>();
    let gate = Gate::new(risk, Permission::RawRci, true)
        .persisting(persists)
        .recovery(
            items
                .iter()
                .any(|(_item, validated)| validated.contains_management()),
        );
    if !persists && !persisted_paths.is_empty() {
        ctx.out().note(&ctx.out().tr(
            keys::CLI_MIXED_PERSISTENCE_BEFORE,
            &[("paths", persisted_paths.join(", ").as_str())],
        ));
    }
    let mut responses = Vec::new();
    let mut completed_persists = false;
    let mut unsaved = false;
    let mut completed_paths = Vec::new();
    let mut applied_changes = 0_usize;
    let mut audit = None;
    let mut recovery_failure = None;
    let completion = run_completed(ctx, services, target, gate, async |changes, _router| {
        let request = BatchChangeRequest::new(
            items.into_iter().map(|(item, _validated)| item).collect(),
            Vec::new(),
            Permission::RawRci,
            json!({ "method": "POST" }),
        );
        let result = changes.apply_batch(request).await?;
        completed_persists = result.persists_immediately;
        unsaved = result.unsaved;
        applied_changes = result.applied_changes;
        let applied_management_changes = result.applied_management_changes;
        completed_paths = result.persisted_paths;
        responses = result.responses;
        audit = Some(result.audit);
        Ok((Value::Null, applied_management_changes != 0))
    })
    .await;
    let router_unsaved = completion.as_ref().ok().map(|(_document, held)| *held);
    if let Err(failure) = completion {
        if responses.iter().all(Result::is_ok) {
            return Err(failure);
        }
        ctx.out().note(&failure.headline(ctx.out().locale()));
        recovery_failure = Some(failure);
    }
    let failed = responses
        .iter()
        .filter(|response| response.is_err())
        .count();
    if failed != 0 {
        ctx.out().note(&ctx.out().tr(
            keys::CLI_BATCH_REFUSED,
            &[
                ("succeeded", &applied_changes.to_string()),
                ("failed", &failed.to_string()),
            ],
        ));
    } else if !completed_persists && !completed_paths.is_empty() {
        ctx.out().note(&ctx.out().tr(
            keys::CLI_MIXED_PERSISTENCE,
            &[("paths", completed_paths.join(", ").as_str())],
        ));
    } else {
        let note = saved_note(
            (unsaved, completed_persists && applied_changes != 0),
            router_unsaved,
            applied_changes,
        );
        if let Some(key) = note {
            ctx.out().note(&ctx.out().tr(key, &[]));
        }
    }
    let audit_pending = audit.as_ref().is_some_and(AuditReceipt::is_pending);
    report(
        ctx,
        shown(ctx, target, responses),
        (unsaved, completed_persists, &completed_paths, audit_pending),
        recovery_failure,
    )
}

/// The headline after a batch that applied cleanly.
///
/// The change waits for a save (by its paths or by the router's flag), the router stored it
/// already, or the router holds nothing unsaved after changes that left configuration alone.
const fn saved_note(
    (unsaved, persisted): (bool, bool),
    router_unsaved: Option<bool>,
    applied_changes: usize,
) -> Option<MessageKey> {
    if unsaved || matches!(router_unsaved, Some(true)) {
        Some(keys::CLI_APPLIED)
    } else if persisted {
        Some(keys::CLI_APPLIED_PERSISTED)
    } else if matches!(router_unsaved, Some(false)) && applied_changes != 0 {
        Some(keys::CLI_DONE)
    } else {
        None
    }
}

/// Authorizes and reports a read-only batch without a change workflow.
///
/// # Errors
/// Returns authorization, transport or per-item failures.
// cancel-safe: only catalog-validated reads reach the router.
async fn read_batch(
    ctx: &Ctx,
    target: &Target,
    items: &[(BatchItem, ValidatedRequest)],
) -> Outcome {
    drop(
        ctx.principal()
            .authorize(&[Permission::Read], &[target.id()])?,
    );
    let values = items
        .iter()
        .map(|(item, _validated)| item.value.expose_for_send().expose_secret().clone())
        .collect();
    let responses = target
        .router()
        .client
        .batch(values)
        .await
        .map_err(RciError::from)?;
    report(
        ctx,
        shown(ctx, target, responses),
        (false, false, &[], false),
        None,
    )
}

/// `responses` of `target` with their secrets redacted unless the principal may see them.
fn shown(
    ctx: &Ctx,
    target: &Target,
    mut responses: Vec<Result<RciResponse, RciError>>,
) -> Vec<Result<RciResponse, RciError>> {
    for response in responses.iter_mut().flatten() {
        mask_unless_revealed(ctx, target, &mut response.value);
    }
    responses
}

/// Prints per-item results; any failed item makes the command partial (exit 7).
///
/// `left` says what the items left: unsaved changes, changes persisted at once, the
/// persisted paths, and an audit entry still queued.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
fn report(
    ctx: &Ctx,
    responses: Vec<Result<RciResponse, RciError>>,
    left: (bool, bool, &[String], bool),
    recovery_failure: Option<Failure>,
) -> Outcome {
    let (unsaved, persists, persisted_paths, audit_pending) = left;
    let failed = responses
        .iter()
        .filter(|response| response.is_err())
        .count();
    let items = responses
        .into_iter()
        .map(|response| match response {
            Ok(value) => json!({ "ok": true, "value": body_value(RciBody::Json(value)) }),
            Err(RciError::Rci {
                message,
                pointer: _,
                code: _,
                ident: _,
            }) => json!({ "ok": false, "error": message }),
            Err(error) => json!({ "ok": false, "error": error.to_string() }),
        })
        .collect::<Vec<_>>();
    let mut document = labelled(json!({ "items": items, "unsaved": unsaved }), persists);
    if (!persists || failed != 0)
        && !persisted_paths.is_empty()
        && let Value::Object(object) = &mut document
    {
        drop(object.insert("persisted_paths".to_owned(), json!(persisted_paths)));
    }
    if audit_pending && let Value::Object(object) = &mut document {
        drop(object.insert("audit_pending".to_owned(), Value::Bool(true)));
    }
    ctx.out()
        .emit(&document, &serde_json::to_string_pretty(&document)?)?;
    if failed == 0 {
        Ok(())
    } else if let Some(failure) = recovery_failure {
        Err(failure.at_exit(Exit::Partial))
    } else {
        Err(Failure::new(Exit::Partial, Detail::None))
    }
}

/// Validates one root object or a batch array against the catalog.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
fn root_items(
    catalog: &Catalog,
    value: Value,
    batch_only: bool,
) -> Outcome<Vec<(BatchItem, ValidatedRequest)>> {
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
            Ok((BatchItem::new(item), validated))
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
) -> Outcome<ValidatedRequest> {
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
