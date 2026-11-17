//! Secrets at rest: XChaCha20-Poly1305 under a 32-byte master key.
//!
//! The master key lives in the config directory (or the file named by
//! `KCC_MASTER_KEY_FILE`), never in the state directory, so a copy of the
//! state directory does not carry its own key. Each sealed value gets a fresh
//! random 192-bit nonce, and its [`Binding`] (the record type and owner) is the
//! associated data, so a ciphertext moved to another record fails to open.

pub mod binding;
pub mod files;

use core::{fmt, str};
use std::{
    env,
    fs::{self, File},
    io::{self, Read, Write as _},
    path::{Path, PathBuf},
    process,
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use chacha20poly1305::{
    KeyInit as _, XChaCha20Poly1305, XNonce,
    aead::{Aead as _, Generate as _, Payload},
};
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use self::binding::Binding;
use crate::{
    persist::{StateError, create_private_dir, create_private_file},
    settings::default_config_dir,
};

/// Environment variable naming the master key file.
pub const MASTER_KEY_FILE_ENV: &str = "KCC_MASTER_KEY_FILE";
/// Master key file name inside the config directory.
const MASTER_KEY_FILE: &str = "master.key";
/// Master key length in bytes.
const KEY_LEN: usize = 32;
/// Algorithm label stored with every sealed value.
const ALGORITHM: &str = "xchacha20poly1305";

/// Length of the Poly1305 tag that ends every ciphertext.
const TAG_LEN: usize = 16;

/// Error sealing or opening a secret, or handling the master key.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CryptoError {
    /// Wrong key, wrong associated data, or tampered ciphertext.
    #[error("secret cannot be decrypted (wrong master key or tampered data)")]
    Decrypt,
    /// Encryption failed.
    #[error("secret cannot be encrypted")]
    Encrypt,
    /// A sealed value is malformed.
    #[error("sealed secret is malformed: {reason}")]
    Malformed {
        /// What is wrong.
        reason: &'static str,
    },
    /// The OS random number generator failed.
    #[error("OS random number generator failed: {reason}")]
    Rng {
        /// RNG error text.
        reason: String,
    },
    /// The master key file cannot be read or created.
    #[error("master key file {path}: {source}")]
    KeyFile {
        /// Key file path.
        path: PathBuf,
        /// Underlying I/O error.
        source: io::Error,
    },
    /// The master key file is not exactly 32 bytes.
    #[error("master key file {path} must hold exactly 32 bytes")]
    KeyLength {
        /// Key file path.
        path: PathBuf,
    },
    /// The master key file is readable by group or others.
    #[error("master key file {path} must not be accessible by group or others (chmod 600)")]
    KeyPermissions {
        /// Key file path.
        path: PathBuf,
    },
    /// No key file is configured and the platform has no config directory.
    #[error("no {MASTER_KEY_FILE_ENV} set and no platform config directory is known")]
    NoKeyPath,
    /// Creating the key's directory failed.
    #[error(transparent)]
    State(#[from] StateError),
}

/// The 32-byte master key. Zeroized on drop; `Debug` never shows it.
#[non_exhaustive]
pub struct MasterKey {
    /// Key bytes.
    bytes: Zeroizing<[u8; KEY_LEN]>,
}

impl fmt::Debug for MasterKey {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MasterKey([REDACTED])")
    }
}

/// A sealed secret as stored in state files.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct SealedSecret {
    /// Algorithm label, always `xchacha20poly1305`.
    pub alg: String,
    /// Base64 24-byte nonce.
    pub nonce: String,
    /// Base64 ciphertext with the Poly1305 tag.
    pub ciphertext: String,
}

impl SealedSecret {
    /// The length in bytes of the plaintext, read from the ciphertext's length without
    /// opening it: the ciphertext is the plaintext followed by the Poly1305 tag. A damaged
    /// record answers a wrong length; opening it fails.
    #[inline]
    #[must_use]
    pub fn plaintext_len(&self) -> u64 {
        let padding = self
            .ciphertext
            .bytes()
            .rev()
            .take_while(|byte| *byte == b'=')
            .count();
        let decoded = self
            .ciphertext
            .len()
            .div_euclid(4)
            .saturating_mul(3)
            .saturating_sub(padding);
        u64::try_from(decoded.saturating_sub(TAG_LEN)).unwrap_or(u64::MAX)
    }
}

impl MasterKey {
    /// Wraps raw key bytes.
    #[inline]
    #[must_use]
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self {
            bytes: Zeroizing::new(bytes),
        }
    }

    /// An independent copy of this key for another store that shares it, such as the
    /// settings presets beside the backups; zeroized on drop like the original.
    #[inline]
    #[must_use]
    pub fn duplicate(&self) -> Self {
        Self {
            bytes: Zeroizing::new(*self.bytes),
        }
    }

    /// Generates a key from the OS RNG.
    ///
    /// # Errors
    ///
    /// [`CryptoError::Rng`] when the OS RNG fails.
    #[inline]
    pub fn generate() -> Result<Self, CryptoError> {
        let mut bytes = Zeroizing::new([0_u8; KEY_LEN]);
        *bytes = <[u8; KEY_LEN]>::try_generate().map_err(|error| CryptoError::Rng {
            reason: error.to_string(),
        })?;
        Ok(Self { bytes })
    }

    /// Reads the key at `path`.
    ///
    /// # Errors
    ///
    /// [`CryptoError::KeyFile`], [`CryptoError::KeyLength`], or (unix)
    /// [`CryptoError::KeyPermissions`] when group or others have access.
    #[inline]
    pub fn load(path: &Path) -> Result<Self, CryptoError> {
        let key_file = |source| CryptoError::KeyFile {
            path: path.to_owned(),
            source,
        };
        let mut file = File::open(path).map_err(key_file)?;
        check_key_permissions(&file, path)?;
        let mut contents = Zeroizing::new(Vec::with_capacity(KEY_LEN));
        let _: usize = Read::take(
            &mut file,
            u64::try_from(KEY_LEN).unwrap_or(u64::MAX).saturating_add(1),
        )
        .read_to_end(&mut contents)
        .map_err(key_file)?;
        let bytes = <[u8; KEY_LEN]>::try_from(contents.as_slice()).map_err(|_error| {
            CryptoError::KeyLength {
                path: path.to_owned(),
            }
        })?;
        Ok(Self::from_bytes(bytes))
    }

    /// Reads the key at `path`, creating it (owner-only, from the OS RNG) on
    /// first run. Concurrent first runs agree on one key: the new key is
    /// published with a hard link, which never replaces an existing file.
    ///
    /// # Errors
    ///
    /// As [`Self::load`] and [`Self::generate`], plus creation failures.
    #[inline]
    pub fn load_or_create(path: &Path) -> Result<Self, CryptoError> {
        match Self::load(path) {
            Err(CryptoError::KeyFile { source, path: _ })
                if source.kind() == io::ErrorKind::NotFound => {}
            other => return other,
        }
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let key_file = |source| CryptoError::KeyFile {
            path: path.to_owned(),
            source,
        };
        // Only a directory kcc creates is made owner-only; an existing parent,
        // such as a home directory, keeps the mode its owner chose.
        match fs::symlink_metadata(parent) {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => create_private_dir(parent)?,
            Err(error) => return Err(key_file(error)),
        }
        let key = Self::generate()?;
        let temp = parent.join(format!(".{MASTER_KEY_FILE}.{}.tmp", process::id()));
        if let Err(error) = write_key(&temp, &key) {
            // Best-effort cleanup; the write error is what the caller needs.
            drop(fs::remove_file(&temp));
            return Err(error);
        }
        let linked = fs::hard_link(&temp, path);
        fs::remove_file(&temp).map_err(key_file)?;
        match linked {
            Ok(()) => Ok(key),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Self::load(path),
            Err(error) => Err(key_file(error)),
        }
    }

    /// Seals `plaintext` with `binding` as associated data.
    ///
    /// # Errors
    ///
    /// [`CryptoError::Rng`] or [`CryptoError::Encrypt`].
    #[inline]
    pub fn seal(
        &self,
        binding: &Binding,
        plaintext: &SecretString,
    ) -> Result<SealedSecret, CryptoError> {
        let nonce = XNonce::try_generate().map_err(|error| CryptoError::Rng {
            reason: error.to_string(),
        })?;
        let payload = Payload {
            msg: plaintext.expose_secret().as_bytes(),
            aad: binding.as_bytes(),
        };
        let ciphertext = self
            .cipher()?
            .encrypt(&nonce, payload)
            .map_err(|_error| CryptoError::Encrypt)?;
        Ok(SealedSecret {
            alg: ALGORITHM.to_owned(),
            nonce: STANDARD.encode(nonce.as_slice()),
            ciphertext: STANDARD.encode(ciphertext),
        })
    }

    /// Opens a secret sealed with `binding`.
    ///
    /// # Errors
    ///
    /// [`CryptoError::Decrypt`] for a wrong key, another binding or tampered data;
    /// [`CryptoError::Malformed`] for a damaged record.
    #[inline]
    pub fn open(
        &self,
        binding: &Binding,
        sealed: &SealedSecret,
    ) -> Result<SecretString, CryptoError> {
        if sealed.alg != ALGORITHM {
            return Err(CryptoError::Malformed {
                reason: "unknown algorithm",
            });
        }
        let nonce_bytes =
            STANDARD
                .decode(&sealed.nonce)
                .map_err(|_error| CryptoError::Malformed {
                    reason: "nonce is not base64",
                })?;
        let nonce =
            XNonce::try_from(nonce_bytes.as_slice()).map_err(|_error| CryptoError::Malformed {
                reason: "nonce is not 24 bytes",
            })?;
        let ciphertext =
            STANDARD
                .decode(&sealed.ciphertext)
                .map_err(|_error| CryptoError::Malformed {
                    reason: "ciphertext is not base64",
                })?;
        let payload = Payload {
            msg: &ciphertext,
            aad: binding.as_bytes(),
        };
        let plaintext = Zeroizing::new(
            self.cipher()?
                .decrypt(&nonce, payload)
                .map_err(|_error| CryptoError::Decrypt)?,
        );
        str::from_utf8(&plaintext)
            .map(SecretString::from)
            .map_err(|_error| CryptoError::Malformed {
                reason: "plaintext is not UTF-8",
            })
    }

    /// Builds the cipher for this key.
    ///
    /// # Errors
    ///
    /// [`CryptoError::Malformed`] if the key length is wrong (it never is).
    fn cipher(&self) -> Result<XChaCha20Poly1305, CryptoError> {
        XChaCha20Poly1305::new_from_slice(self.bytes.as_slice()).map_err(|_error| {
            CryptoError::Malformed {
                reason: "master key length",
            }
        })
    }
}

/// The master key path: `KCC_MASTER_KEY_FILE`, else `<config dir>/master.key`.
///
/// # Errors
///
/// [`CryptoError::NoKeyPath`] when neither is available.
#[inline]
pub fn master_key_path() -> Result<PathBuf, CryptoError> {
    env::var_os(MASTER_KEY_FILE_ENV)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| default_config_dir().map(|dir| dir.join(MASTER_KEY_FILE)))
        .ok_or(CryptoError::NoKeyPath)
}

/// Writes the key to a new owner-only file and syncs it.
///
/// # Errors
///
/// [`CryptoError::State`] or [`CryptoError::KeyFile`].
fn write_key(path: &Path, key: &MasterKey) -> Result<(), CryptoError> {
    let mut file = create_private_file(path)?;
    file.write_all(key.bytes.as_slice())
        .and_then(|()| file.sync_all())
        .map_err(|source| CryptoError::KeyFile {
            path: path.to_owned(),
            source,
        })
}

/// Refuses a key file group or others can access (unix only).
///
/// # Errors
///
/// [`CryptoError::KeyPermissions`] or [`CryptoError::KeyFile`].
fn check_key_permissions(file: &File, path: &Path) -> Result<(), CryptoError> {
    let metadata = file.metadata().map_err(|source| CryptoError::KeyFile {
        path: path.to_owned(),
        source,
    })?;
    files::owner_only(&metadata, path).map_err(|_error| CryptoError::KeyPermissions {
        path: path.to_owned(),
    })
}
