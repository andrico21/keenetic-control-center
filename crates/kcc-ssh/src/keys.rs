//! Credentials and host key pins.

use core::fmt;

use rand::RngExt as _;
use russh::keys::{
    Algorithm, HashAlg, PrivateKey, PublicKey, decode_secret_key,
    ssh_key::{LineEnding, private::Ed25519Keypair, public::Ed25519PublicKey},
};
use secrecy::{ExposeSecret as _, SecretString};
use zeroize::Zeroizing;

use crate::error::SshError;

/// How a [`Slot`](crate::pool::Slot) authenticates as `root`.
///
/// `Debug` shows the variant only; the secret is exposed once, at the russh call.
#[derive(Debug)]
#[non_exhaustive]
pub enum Auth {
    /// The Entware root password, typed by an admin for enrolment.
    ///
    /// russh copies the password into a plain `String` for its authentication request;
    /// that copy is not zeroized when russh drops it.
    Password(SecretString),
    /// An OpenSSH-format ed25519 private key, as [`generate_ed25519`] returns it.
    Key(SecretString),
}

/// Parses the private key of [`Auth::Key`]; it must be ed25519.
///
/// # Errors
///
/// Returns [`SshError::InvalidKey`] for text that is no OpenSSH ed25519 private key.
pub(crate) fn private_key(key: &SecretString) -> Result<PrivateKey, SshError> {
    decode_secret_key(key.expose_secret(), None)
        .ok()
        .filter(|private| private.algorithm() == Algorithm::Ed25519)
        .ok_or(SshError::InvalidKey)
}

/// A pinned ed25519 host key: the 32 public key bytes the server must present.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub struct HostKeyPin([u8; Ed25519PublicKey::BYTE_SIZE]);

impl HostKeyPin {
    /// Parses a stored pin, `ssh-ed25519 <base64>` (a trailing comment is ignored).
    ///
    /// # Errors
    ///
    /// Returns [`SshError::InvalidKey`] for unparsable text and
    /// [`SshError::UnsupportedHostKey`] for another algorithm.
    #[inline]
    pub fn from_openssh(text: &str) -> Result<Self, SshError> {
        let key = PublicKey::from_openssh(text).map_err(|_unparsable| SshError::InvalidKey)?;
        Self::from_key(&key)
    }

    /// The pin as `ssh-ed25519 <base64>`, the form [`HostKeyPin::from_openssh`] reads.
    ///
    /// # Errors
    ///
    /// Returns [`SshError::InvalidKey`] when the key cannot be encoded.
    #[inline]
    pub fn to_openssh(self) -> Result<String, SshError> {
        self.public_key()
            .to_openssh()
            .map_err(|_unencodable| SshError::InvalidKey)
    }

    /// The OpenSSH SHA-256 fingerprint (`SHA256:<base64>`), the form shown to admins.
    #[inline]
    #[must_use]
    pub fn fingerprint(&self) -> String {
        self.public_key().fingerprint(HashAlg::Sha256).to_string()
    }

    /// The pin of `key`.
    ///
    /// # Errors
    ///
    /// Returns [`SshError::UnsupportedHostKey`] unless `key` is ed25519.
    pub(crate) fn from_key(key: &PublicKey) -> Result<Self, SshError> {
        key.key_data()
            .ed25519()
            .map(|ed25519| Self(ed25519.0))
            .ok_or(SshError::UnsupportedHostKey)
    }

    /// The pinned key as an SSH public key.
    fn public_key(self) -> PublicKey {
        PublicKey::from(Ed25519PublicKey(self.0))
    }
}

impl fmt::Debug for HostKeyPin {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("HostKeyPin")
            .field(&self.fingerprint())
            .finish()
    }
}

/// Generates a new ed25519 key pair for one router.
///
/// Returns the private key in OpenSSH format, for [`Auth::Key`], and the public key line
/// `ssh-ed25519 <base64>` (no comment), for
/// [`EntwareCommand::AppendKey`](crate::command::EntwareCommand::AppendKey).
///
/// # Errors
///
/// Returns [`SshError::InvalidKey`] when the key cannot be encoded.
#[inline]
pub fn generate_ed25519() -> Result<(SecretString, String), SshError> {
    let seed = Zeroizing::new(rand::rng().random::<[u8; 32]>());
    let private = PrivateKey::from(Ed25519Keypair::from_seed(&seed));
    let encoded = private
        .to_openssh(LineEnding::LF)
        .map_err(|_unencodable| SshError::InvalidKey)?;
    let line = private
        .public_key()
        .to_openssh()
        .map_err(|_unencodable| SshError::InvalidKey)?;
    Ok((SecretString::from(encoded.as_str()), line))
}
