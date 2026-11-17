//! A password typed in step 5 for a router user whose hash is bound to the source's realm.

use kcc_i18n::{bundle::MessageKey, keys};
use secrecy::SecretString;

/// The longest password kcc passes to a router, in characters.
const PASSWORD_MAX: usize = 256;

/// The password `typed` for a user, `stored` when one is already sealed for it: none
/// when the field was left empty to keep the stored one.
///
/// # Errors
///
/// Returns why it is refused: empty with nothing stored, longer than [`PASSWORD_MAX`]
/// characters, or holding a control character.
pub(crate) fn typed(typed: &str, stored: bool) -> Result<Option<SecretString>, MessageKey> {
    if typed.is_empty() {
        return if stored {
            Ok(None)
        } else {
            Err(keys::WEB_MIGRATE_INPUTS_PASSWORD_MISSING)
        };
    }
    if typed.chars().count() > PASSWORD_MAX || typed.chars().any(char::is_control) {
        return Err(keys::WEB_MIGRATE_INPUTS_PASSWORD_INVALID);
    }
    Ok(Some(SecretString::from(typed.to_owned())))
}
