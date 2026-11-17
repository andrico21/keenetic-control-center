//! The run's report as a file.
//!
//! `GET /ui/presets/runs/{run}/download/{report.json,report.md}`, built from the record
//! alone, so it names routers, groups, counts and public WireGuard keys, never a
//! setting's value.

use alloc::sync::Arc;

use axum::{
    Extension,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse as _, Response},
};
use fluent_bundle::FluentArgs;
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use serde_json::json;

use super::{
    access::Visit,
    record::Record,
    steps::{Finish, Origin},
    summary::settings_text,
};
use crate::{
    WebState,
    admin_shared::Timestamp,
    authz::CurrentUser,
    errors,
    page_kit::{
        context::{Refusal, fragment_shell},
        respond::Answer,
    },
    wizard::{
        flow::Flow as _, report::attachment, run::Ended, service::Wizards, services::Services,
    },
};

/// `GET /ui/presets/runs/{run}/download/{file}`: the report, as an attachment.
///
/// # Errors
///
/// Answers the refusal of the run and 404 for another file name.
// cancel-safe: reads only.
pub(super) async fn download(
    State(state): State<WebState>,
    Path((id, file)): Path<(String, String)>,
    Extension(runs): Extension<Arc<Wizards<Record>>>,
    user: CurrentUser,
) -> Result<Response, Answer> {
    let content_type = match file.as_str() {
        "report.json" => "application/json",
        "report.md" => "text/markdown; charset=utf-8",
        _ => return Err(StatusCode::NOT_FOUND.into_response().into()),
    };
    let services = Services::of(&state, &user).map_err(Refusal::status)?;
    let visit = Visit::open(services, &runs, &id)
        .await
        .map_err(Refusal::status)?;
    let locale = user.locale();
    let body = if file == "report.json" {
        serde_json::to_string_pretty(&report_json(visit.record(), locale))
            .map_err(|error| Answer::from(errors::internal(&error, fragment_shell(locale))))?
    } else {
        markdown(visit.record(), locale)
    };
    drop(visit);
    Ok(attachment(
        body,
        content_type,
        &format!("preset-run-{id}-{file}"),
    ))
}

/// The report as JSON.
fn report_json(record: &Record, locale: Locale) -> serde_json::Value {
    let ended = record.run().and_then(|run| run.ended());
    let (finish, finished_at) = record
        .finished()
        .map_or((None, None), |(how, at)| (Some(how.slug()), Some(at)));
    let preset = match record.origin() {
        Origin::Preset { id, name: _ } => Some(id.clone()),
        Origin::Copy => None,
    };
    json!({
        "run": record.id(),
        "settings": settings_text(record, locale),
        "preset": preset,
        "source_router": record.source_router(),
        "target": record.target(),
        "mode": record.mode().slug(),
        "keep_wireguard_keys": record.keep_keys(),
        "finished": finish,
        "finished_at": finished_at,
        "applied": ended.map(Ended::applied),
        "refused": ended.map(Ended::failed),
        "failure": ended.and_then(|end| end.failure()),
        "wireguard_public_keys": record
            .keys()
            .iter()
            .map(|(interface, key)| json!({ "interface": interface, "public_key": key }))
            .collect::<Vec<_>>(),
        "kept_private_keys": record.kept_keys(),
    })
}

/// The report as Markdown, in `locale`.
fn markdown(record: &Record, locale: Locale) -> String {
    let text = |key| tr(locale, key, None);
    let cell = |value: &str| value.replace('|', "\\|");
    let mut lines = vec![
        format!(
            "# {}: {}",
            text(keys::WEB_MIGRATE_REPORT_TITLE),
            cell(&settings_text(record, locale))
        ),
        String::new(),
        format!(
            "- {}: {}",
            text(keys::MIGRATE_TARGET),
            record.target().unwrap_or_default()
        ),
    ];
    if let Some((how, at)) = record.finished() {
        let when =
            Timestamp::at(at, locale).map_or_else(String::new, |time| time.text().to_owned());
        lines.push(format!(
            "- {}: {} ({when})",
            text(keys::WEB_MIGRATE_REPORT_FINISHED),
            text(how.text())
        ));
    } else {
        lines.push(format!(
            "- {}: {}",
            text(keys::WEB_MIGRATE_REPORT_FINISHED),
            text(Finish::Closed.text())
        ));
    }
    if let Some(end) = record.run().and_then(|run| run.ended()) {
        lines.push(format!(
            "- {}: {}",
            text(keys::WEB_MIGRATE_COUNT_APPLIED),
            end.applied()
        ));
        lines.push(format!(
            "- {}: {}",
            text(keys::WEB_MIGRATE_COUNT_REFUSED),
            end.failed()
        ));
    }
    for name in record.kept_keys() {
        let mut args = FluentArgs::new();
        args.set("name", name.clone());
        lines.push(format!(
            "- {}",
            tr(locale, keys::WEB_PRESETS_KEYS_KEPT, Some(&args))
        ));
    }
    if !record.keys().is_empty() {
        lines.extend([
            String::new(),
            format!("## {}", text(keys::WEB_PRESETS_KEYS_TITLE)),
            String::new(),
            text(keys::WEB_PRESETS_KEYS_TEXT),
            String::new(),
            format!(
                "| {} | {} |",
                text(keys::WEB_PRESETS_KEYS_INTERFACE),
                text(keys::WEB_PRESETS_KEYS_KEY)
            ),
            "| --- | --- |".to_owned(),
        ]);
        lines.extend(
            record
                .keys()
                .iter()
                .map(|(interface, key)| format!("| {} | {} |", cell(interface), cell(key))),
        );
    }
    lines.push(String::new());
    lines.join("\n")
}
