//! The sealed records of one router as they are on disk, kept to put them back after a
//! change that did not complete.

use core::fmt;
use std::{fs, io};

use zeroize::Zeroizing;

use super::{
    CredentialError, CredentialKind, CredentialStore, router_id::RouterId, wipe::remove_if_present,
};
use crate::persist::{io_error, write_atomic};

/// The sealed record bytes of every credential kind of one router (`None` for a kind
/// without a record). It holds only encrypted bytes and never shows them.
#[non_exhaustive]
pub struct SealedRecords {
    /// Router id.
    router: String,
    /// Each kind with its record bytes, if it has a record.
    records: Vec<(CredentialKind, Option<Zeroizing<Vec<u8>>>)>,
}

impl fmt::Debug for SealedRecords {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kinds = self
            .records
            .iter()
            .filter(|(_, bytes)| bytes.is_some())
            .map(|(kind, _)| kind.audit_name())
            .collect::<Vec<_>>();
        f.debug_struct("SealedRecords")
            .field("router", &self.router)
            .field("records", &kinds)
            .finish()
    }
}

impl SealedRecords {
    /// Reads the sealed record of every kind of `router` from `store`.
    ///
    /// # Errors
    /// Returns [`CredentialError::Record`] for an invalid router id, or a typed storage
    /// failure.
    #[inline]
    pub fn take(store: &CredentialStore, router: &str) -> Result<Self, CredentialError> {
        let id = RouterId::parse(router)?;
        let _lock = store.state.lock(&id.lock_name())?;
        let records = CredentialKind::ALL
            .into_iter()
            .map(|kind| {
                let path = store.record_path(id, kind)?;
                match fs::read(&path) {
                    Ok(bytes) => Ok((kind, Some(Zeroizing::new(bytes)))),
                    Err(error) if error.kind() == io::ErrorKind::NotFound => Ok((kind, None)),
                    Err(source) => Err(CredentialError::State(io_error(&path, source))),
                }
            })
            .collect::<Result<_, CredentialError>>()?;
        Ok(Self {
            router: router.to_owned(),
            records,
        })
    }

    /// Puts every record back byte for byte into `store` and removes a record of a kind
    /// that had none.
    ///
    /// # Errors
    /// Returns the first storage failure; the records before it are restored.
    #[inline]
    pub fn restore(&self, store: &CredentialStore) -> Result<(), CredentialError> {
        let router = RouterId::parse(&self.router)?;
        let _lock = store.state.lock(&router.lock_name())?;
        let directory = store.directory()?;
        self.records.iter().try_for_each(|(kind, bytes)| {
            match bytes {
                Some(record) => write_atomic(&directory, &router.file_name(*kind), record)?,
                None => remove_if_present(&store.record_path(router, *kind)?)?,
            }
            Ok(())
        })
    }
}
