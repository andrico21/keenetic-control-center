//! The client CA of the MCP listeners' mTLS sign-in, uploaded on the Web and stored as
//! `<state>/mcp/mtls-ca.pem`.
//!
//! A file is taken when it is at most 64 KiB of PEM holding one to ten certificates and
//! nothing else, each a parseable X.509 certificate whose basic constraints say it is a
//! CA, framed so that the MCP listeners' own PEM reader loads the same certificates. The
//! validity period is not checked: a CA past it admits no client, since the TLS handshake
//! refuses every certificate chaining to it. Certificates are not secret, so on Unix the
//! file is world-readable (`0644`) in the owner-only state directory.

extern crate alloc;

use alloc::string::ToString as _;
use std::{
    fs,
    io::{self, Write as _},
    path::{Path, PathBuf},
};

use rustls::pki_types::{CertificateDer, pem::PemObject as _};
use x509_parser::{certificate::X509Certificate, pem::Pem, prelude::FromDer as _};

use crate::persist::{
    StateError, StateStore, create_private_dir, create_private_file, io_error, sync_dir,
};

/// The state subdirectory of the MCP certificate files.
pub const DIRECTORY: &str = "mcp";

/// The uploaded client CA's file name.
pub const MTLS_CA: &str = "mtls-ca.pem";

/// The largest CA file, in bytes.
pub const FILE_LIMIT: usize = 64 * 1024;

/// The most certificates a CA file may hold.
pub const MAX_CERTIFICATES: usize = 10;

/// Why a client CA file is refused.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CaError {
    /// The file is larger than [`FILE_LIMIT`].
    #[error("the CA file is larger than 64 KiB")]
    TooLarge,
    /// The file holds no PEM block, a block that cannot be decoded, or blocks the MCP
    /// listeners' PEM reader reads differently.
    #[error("the CA file holds no PEM certificate")]
    NotPem,
    /// The file holds a PEM block that is not a certificate (a private key, for example).
    #[error("the CA file holds something besides certificates")]
    OtherBlock,
    /// The file holds more than [`MAX_CERTIFICATES`] certificates.
    #[error("the CA file holds {found} certificates; at most 10 are allowed")]
    Count {
        /// How many it holds.
        found: usize,
    },
    /// A certificate block does not hold an X.509 certificate.
    #[error("certificate {} of the CA file cannot be read", index.saturating_add(1))]
    Unparsable {
        /// Its position in the file, from 0.
        index: usize,
    },
    /// A certificate is not a CA certificate (basic constraints without `CA:TRUE`).
    #[error("certificate {} of the CA file is not a CA certificate", index.saturating_add(1))]
    NotCa {
        /// Its position in the file, from 0.
        index: usize,
    },
    /// The state directory could not be read or written.
    #[error(transparent)]
    State(#[from] StateError),
}

/// The stored client CA file of `store`.
#[inline]
#[must_use]
pub fn mtls_ca_path(store: &StateStore) -> PathBuf {
    store.dir().join(DIRECTORY).join(MTLS_CA)
}

/// Checks `pem` as a client CA file; the subjects of its certificates, in file order.
///
/// # Errors
///
/// A [`CaError`] other than [`CaError::State`] naming the first rule the file breaks.
#[inline]
pub fn check_mtls_ca(pem: &[u8]) -> Result<Vec<String>, CaError> {
    if pem.len() > FILE_LIMIT {
        return Err(CaError::TooLarge);
    }
    let blocks = Pem::iter_from_buffer(pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_undecodable| CaError::NotPem)?;
    if blocks.is_empty() {
        return Err(CaError::NotPem);
    }
    if blocks.iter().any(|block| block.label != "CERTIFICATE") {
        return Err(CaError::OtherBlock);
    }
    if blocks.len() > MAX_CERTIFICATES {
        return Err(CaError::Count {
            found: blocks.len(),
        });
    }
    let contents: Vec<&[u8]> = blocks
        .iter()
        .map(|block| block.contents.as_slice())
        .collect();
    loaded_as_read(pem, &contents)?;
    blocks
        .iter()
        .enumerate()
        .map(|(index, block)| {
            let Ok(([], certificate)) = X509Certificate::from_der(&block.contents) else {
                return Err(CaError::Unparsable { index });
            };
            if certificate.is_ca() {
                Ok(certificate.subject().to_string())
            } else {
                Err(CaError::NotCa { index })
            }
        })
        .collect()
}

/// Requires the MCP listeners' PEM reader to load exactly `contents` from `pem`.
///
/// # Errors
///
/// [`CaError::NotPem`] when it fails, skips a block or reads one differently.
fn loaded_as_read(pem: &[u8], contents: &[&[u8]]) -> Result<(), CaError> {
    let loaded = CertificateDer::pem_slice_iter(pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_unreadable| CaError::NotPem)?;
    let same = loaded.len() == contents.len()
        && loaded
            .iter()
            .zip(contents)
            .all(|(der, block)| der.as_ref() == *block);
    if same { Ok(()) } else { Err(CaError::NotPem) }
}

/// Checks `pem` ([`check_mtls_ca`]) and stores it as the client CA, replacing the
/// previous one atomically; the subjects of its certificates.
///
/// # Errors
///
/// The [`CaError`] of the check; [`CaError::State`] when the file cannot be written.
#[inline]
pub fn store_mtls_ca(store: &StateStore, pem: &[u8]) -> Result<Vec<String>, CaError> {
    stored_as(store, MTLS_CA, pem)
}

/// Checks `pem` ([`check_mtls_ca`]) and stores it as `name` in the MCP directory,
/// replacing the previous file atomically; the subjects of its certificates.
///
/// # Errors
///
/// As [`store_mtls_ca`].
pub(super) fn stored_as(
    store: &StateStore,
    name: &str,
    pem: &[u8],
) -> Result<Vec<String>, CaError> {
    let subjects = check_mtls_ca(pem)?;
    let _lock = store.lock(name)?;
    let dir = store.dir().join(DIRECTORY);
    create_private_dir(&dir)?;
    publish(&dir, name, pem)?;
    Ok(subjects)
}

/// Puts `previous` back as the client CA file unchecked, or removes the file when there
/// was none: undoes a [`store_mtls_ca`] whose listeners could not use the new CA.
///
/// # Errors
///
/// [`CaError::State`] when the file cannot be written or removed.
#[inline]
pub fn restore_mtls_ca(store: &StateStore, previous: Option<&[u8]>) -> Result<(), CaError> {
    restored_as(store, MTLS_CA, previous)
}

/// Puts `previous` back as the file `name` of the MCP directory unchecked, or removes it
/// when there was none.
///
/// # Errors
///
/// As [`restore_mtls_ca`].
pub(super) fn restored_as(
    store: &StateStore,
    name: &str,
    previous: Option<&[u8]>,
) -> Result<(), CaError> {
    let _lock = store.lock(name)?;
    let dir = store.dir().join(DIRECTORY);
    match previous {
        Some(bytes) => publish(&dir, name, bytes)?,
        None => match fs::remove_file(dir.join(name)) {
            Ok(()) => sync_dir(&dir)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(io_error(&dir.join(name), error).into()),
        },
    }
    Ok(())
}

/// The stored client CA file as it is, unchecked; `None` when none is stored.
///
/// # Errors
///
/// [`CaError::State`] when the file cannot be read.
#[inline]
pub fn read_mtls_ca(store: &StateStore) -> Result<Option<Vec<u8>>, CaError> {
    read_as(&mtls_ca_path(store))
}

/// The file at `path` as it is; `None` when it does not exist.
///
/// # Errors
///
/// [`CaError::State`] when the file cannot be read.
pub(super) fn read_as(path: &Path) -> Result<Option<Vec<u8>>, CaError> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(io_error(path, error).into()),
    }
}

/// The subjects of the stored client CA's certificates; `None` when none is stored.
///
/// # Errors
///
/// The stored file breaks a rule of [`check_mtls_ca`] or cannot be read.
#[inline]
pub fn mtls_ca_subjects(store: &StateStore) -> Result<Option<Vec<String>>, CaError> {
    read_mtls_ca(store)?
        .map(|bytes| check_mtls_ca(&bytes))
        .transpose()
}

/// Writes `bytes` to a new temporary file in `dir`, makes it world-readable, syncs it and
/// renames it over the file `name`, then syncs `dir`; the temporary file is removed again
/// when a step fails.
///
/// # Errors
///
/// [`StateError::Io`].
fn publish(dir: &Path, name: &str, bytes: &[u8]) -> Result<(), StateError> {
    let temp = dir.join(format!(".{name}.tmp"));
    match fs::remove_file(&temp) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(io_error(&temp, error)),
    }
    let target = dir.join(name);
    let mut file = create_private_file(&temp)?;
    let written = file
        .write_all(bytes)
        .and_then(|()| readable(&file))
        .and_then(|()| file.sync_all());
    drop(file);
    let published = written
        .map_err(|error| io_error(&temp, error))
        .and_then(|()| fs::rename(&temp, &target).map_err(|error| io_error(&target, error)));
    if published.is_err() {
        // Best-effort cleanup of our own temporary file; the first error is the one to report.
        drop(fs::remove_file(&temp));
    }
    published?;
    sync_dir(dir)
}

/// Makes `file` readable by everyone (`0644`): certificates are not secret.
///
/// # Errors
///
/// The permission change failed.
#[cfg(unix)]
fn readable(file: &fs::File) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    file.set_permissions(fs::Permissions::from_mode(0o644))
}

/// Leaves `file` owner-only: Windows has no world-readable mode bits.
///
/// # Errors
///
/// Never.
#[cfg(not(unix))]
fn readable(_file: &fs::File) -> io::Result<()> {
    Ok(())
}
