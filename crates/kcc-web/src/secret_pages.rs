//! Write-only secret fields of the router pages.
//!
//! The Wi-Fi password of an access point, the password of a PPP internet connection,
//! router-account passwords, VPN client credentials and the VPN servers' pre-shared key
//! and account passwords.
//!
//! Each secret has its own dialog (`partials/secret_dialog.html`): the new value typed
//! twice, never a stored one, so no page can show a secret; both fields left empty keep
//! the stored value and send nothing. The value travels only in the form body, straight
//! into a `SecretString`, through the domain's planner and the change workflow, whose
//! read-back checks that the router reports a stored value of a plausible length, never
//! the value itself. Pages, toasts, the audit log and the server log carry field names
//! only. Seeing a stored secret stays the separate, audited Reveal action.
//!
//! Routes (route table: `Read` and the router scope; every write re-checks its operation's
//! permissions, so a viewer gets 403):
//!
//! - `GET|POST /ui/r/{router}/wifi/psk?name=`: an access point's Wi-Fi password (8 to 63
//!   characters, checked in the browser and again here before anything is sent).
//! - `GET|POST /ui/r/{router}/internet/password?name=`: a PPP connection's password.
//! - `GET|POST /ui/r/{router}/system/users/password?name=`: a router account's password
//!   (management: the dialog explains the fail-safe timer and its Apply confirms; the
//!   account kcc signs in with is refused before anything is sent).
//! - `GET|POST /ui/r/{router}/vpn/credential?kind=&name=`: a VPN client's password,
//!   IPsec pre-shared key or `XAuth` password.
//! - `GET|POST /ui/r/{router}/vpn/server/psk` and `.../vpn/server/password`: the IPsec
//!   server's IKE key and a VPN account's password.

pub(crate) mod dialog;
pub(crate) mod reply;
pub(crate) mod routes;
mod user_password;
pub(crate) mod vpn_credential;
mod vpn_server;
mod wan_password;
mod wifi_psk;
