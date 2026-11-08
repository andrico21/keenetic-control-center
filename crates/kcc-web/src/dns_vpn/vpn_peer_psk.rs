//! The preshared key typed into the peer dialog.
//!
//! It is write-only, taken out of the form before anything else reads it, and written by
//! the VPN client domain in the same change as the peer, with a read-back that checks
//! only that the router reports a key.

use kcc_app::workflow::CliChangeRequest;
use kcc_domain::{Result as DomainResult, RouterCtx, vpn_clients};
use secrecy::SecretString;

use super::form::Values;
use crate::{page_kit::secret::write_only, secret_pages::dialog::take};

/// The form field of the key.
const FIELD: &str = "psk";

/// Takes the key out of `pairs`: the typed key, or `None` when the field was empty, which
/// keeps the peer's stored key.
pub(crate) fn typed(pairs: &mut Vec<(String, String)>) -> Option<SecretString> {
    write_only(take(pairs, FIELD))
}

/// A preshared key for one peer of one connection.
pub(crate) struct PeerKey {
    /// The connection.
    tunnel: String,
    /// The peer's public key.
    public_key: String,
    /// The typed key.
    psk: SecretString,
}

impl PeerKey {
    /// The key `psk` for the peer the dialog's checked `values` name.
    pub(crate) fn new(values: &Values, psk: SecretString) -> Self {
        Self {
            tunnel: values.get("tunnel").trim().to_owned(),
            public_key: values.get("key").trim().to_owned(),
            psk,
        }
    }

    /// `request` with the key's protected write and its read-back appended.
    ///
    /// # Errors
    ///
    /// Returns the catalog's findings about the key.
    pub(crate) fn joined(
        self,
        mut request: CliChangeRequest,
        ctx: &RouterCtx,
    ) -> DomainResult<CliChangeRequest> {
        let operation =
            vpn_clients::plan_wireguard_peer_psk(ctx, &self.tunnel, &self.public_key, self.psk)?;
        let written = vpn_clients::change_request(&operation)?;
        request.commands.extend(written.commands);
        request.verify.extend(written.verify);
        Ok(request)
    }
}
