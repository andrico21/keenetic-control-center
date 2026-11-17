//! The plan and its report as files.
//!
//! `GET /ui/migrate/{id}/download/{file}` with `plan.json` (the plan's redacted form),
//! `report.json`, `report.md` and `report.html`, all built from redacted plan fields
//! only: the plan as it would be built now, or from the apply on the one it used.

use alloc::sync::Arc;

use axum::{
    Extension,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse as _, Response},
};
use kcc_migrate::report::MigrationReport;

use super::{
    access::{Migration as _, Visit},
    plan::Built,
    record::Record,
};
use crate::{
    WebState,
    authz::CurrentUser,
    errors,
    page_kit::{
        context::{Refusal, fragment_shell},
        respond::{Answer, attachment},
    },
    wizard::{service::Wizards, services::Services, store::Kept},
};

/// `GET /ui/migrate/{id}/download/{file}`: one of the plan's files, as an attachment.
///
/// # Errors
///
/// Answers the refusal of the migration, 404 for another file name and 409 while the
/// plan cannot be built.
pub(super) async fn download(
    State(state): State<WebState>,
    Path((id, file)): Path<(String, String)>,
    Extension(wizards): Extension<Arc<Wizards<Record>>>,
    user: CurrentUser,
) -> Result<Response, Answer> {
    let content_type = match file.as_str() {
        "plan.json" | "report.json" => "application/json",
        "report.md" => "text/markdown; charset=utf-8",
        "report.html" => "text/html; charset=utf-8",
        _ => return Err(StatusCode::NOT_FOUND.into_response().into()),
    };
    let services = Services::of(&state, &user).map_err(Refusal::status)?;
    let visit = Visit::open(services, &wizards, &id)
        .await
        .map_err(Refusal::status)?;
    let conflict = || Answer::from(StatusCode::CONFLICT.into_response());
    let store = services.store();
    let kept = (
        store
            .kept(&id, Kept::Report)
            .await
            .map_err(|_error| conflict())?,
        store
            .kept(&id, Kept::Plan)
            .await
            .map_err(|_error| conflict())?,
    );
    let (report, plan) = if let (Some(report), Some(plan)) = kept {
        (
            serde_json::from_str::<MigrationReport>(&report).map_err(|_error| conflict())?,
            plan,
        )
    } else {
        let analysis = visit.analysis().await.map_err(|_problem| conflict())?;
        let passwords = visit.passwords().await.map_err(|_error| conflict())?;
        let built =
            Built::new(&analysis, visit.record(), &passwords).map_err(|_error| conflict())?;
        let plan = serde_json::to_string_pretty(built.plan()).map_err(|_error| conflict())?;
        (
            MigrationReport::from_plan(built.plan(), user.locale()),
            plan,
        )
    };
    drop(visit);
    let rendered = match file.as_str() {
        "plan.json" => Ok(plan),
        "report.json" => report.to_json().map_err(|error| error.to_string()),
        "report.html" => report
            .to_html(user.locale())
            .map_err(|error| error.to_string()),
        _ => Ok(report.to_markdown(user.locale())),
    };
    let body = rendered
        .map_err(|error| Answer::from(errors::internal(&error, fragment_shell(user.locale()))))?;
    Ok(attachment(
        body,
        content_type,
        &format!("migration-{id}-{file}"),
    ))
}
