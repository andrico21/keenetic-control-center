//! `GET /ui/admin/mcp/certificate`: the dedicated listener's self-signed certificate as a
//! PEM download; never its key.

use std::fs;

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse as _, Response},
};
use tokio::task::spawn_blocking;

use super::{
    page::{CERTIFICATE, DIRECTORY},
    pem,
};
use crate::{WebState, admin_shared::unavailable, page_kit::respond};

/// `GET /ui/admin/mcp/certificate`; 404 until kcc made the certificate.
// cancel-safe: it only reads the certificate file on a blocking thread.
pub(crate) async fn download(State(state): State<WebState>) -> Response {
    let Some(admin) = state.admin() else {
        return unavailable(None);
    };
    let path = admin.state().dir().join(DIRECTORY).join(CERTIFICATE);
    let read = spawn_blocking(move || fs::read_to_string(path).ok()).await;
    match read.ok().flatten() {
        Some(text) if pem::certificates(text.as_bytes()).is_some() => {
            respond::attachment(text, "application/x-pem-file", "kcc-mcp-dedicated.pem")
        }
        Some(_) | None => StatusCode::NOT_FOUND.into_response(),
    }
}
