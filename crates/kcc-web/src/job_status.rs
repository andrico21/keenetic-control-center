//! The status pill of a background job, shared by the explorer's and the system pages'
//! job streams.

use askama::Template;
use axum::response::sse::Event;
use kcc_app::jobs::JobStatus;
use kcc_i18n::{bundle::MessageKey, keys, locale::Locale};

use crate::{
    overview::fragment,
    page::{Localize as _, Shell},
    page_kit::context::fragment_shell,
};

/// The status pill of a job.
#[derive(Template)]
#[template(
    ext = "html",
    source = "<span class=\"status\" data-status=\"{{ status }}\">{{ t(*label) }}</span>"
)]
struct StatusView {
    /// Locale carrier.
    shell: Shell,
    /// `data-status` value.
    status: &'static str,
    /// Label.
    label: MessageKey,
}

localized!(StatusView);

/// The `status` event of a job in `status`, in `locale`.
pub(crate) fn event(status: JobStatus, locale: Locale) -> Event {
    let (value, label) = match status {
        JobStatus::Running => ("running", keys::WEB_EXPLORER_JOB_RUNNING),
        JobStatus::Completed => ("done", keys::WEB_EXPLORER_JOB_COMPLETED),
        JobStatus::Cancelled => ("failed", keys::WEB_EXPLORER_JOB_CANCELLED_LABEL),
        JobStatus::Failed | JobStatus::Interrupted | _ => ("failed", keys::WEB_EXPLORER_JOB_FAILED),
    };
    fragment(
        "status",
        &StatusView {
            shell: fragment_shell(locale),
            status: value,
            label,
        },
    )
}
