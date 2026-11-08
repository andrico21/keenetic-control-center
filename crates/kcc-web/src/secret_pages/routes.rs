//! The routes of the secret dialogs.

use axum::{Router, routing::get};

use super::{user_password, vpn_credential, vpn_server, wan_password, wifi_psk};
use crate::WebState;

/// The secret dialogs and their writes.
pub(crate) fn routes() -> Router<WebState> {
    Router::new()
        .route(
            "/ui/r/{router}/wifi/psk",
            get(wifi_psk::psk_dialog).post(wifi_psk::psk),
        )
        .route(
            "/ui/r/{router}/internet/password",
            get(wan_password::password_dialog).post(wan_password::password),
        )
        .route(
            "/ui/r/{router}/system/users/password",
            get(user_password::password_dialog).post(user_password::password),
        )
        .route(
            "/ui/r/{router}/vpn/credential",
            get(vpn_credential::credential_dialog).post(vpn_credential::credential),
        )
        .route(
            "/ui/r/{router}/vpn/server/psk",
            get(vpn_server::psk_dialog).post(vpn_server::psk),
        )
        .route(
            "/ui/r/{router}/vpn/server/password",
            get(vpn_server::password_dialog).post(vpn_server::password),
        )
}
