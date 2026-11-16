//! Job identifier allocation.

use chacha20poly1305::aead::Generate as _;

use super::JobError;

/// Allocates job identifiers.
pub(super) struct JobIdAllocator {
    /// Draws the next identifier.
    next: fn() -> Result<String, JobError>,
}

impl JobIdAllocator {
    /// Draws every identifier from the operating system ([`random_id`]).
    pub(super) const fn system() -> Self {
        Self { next: random_id }
    }

    /// Answers `job-fixed` to every allocation, to force a collision.
    #[cfg(test)]
    pub(super) const fn fixed() -> Self {
        Self {
            next: || Ok("job-fixed".to_owned()),
        }
    }

    /// Allocates one identifier.
    ///
    /// # Errors
    ///
    /// [`JobError::IdUnavailable`] when the operating system yields no random bytes.
    pub(super) fn allocate(&self) -> Result<String, JobError> {
        (self.next)()
    }
}

/// An unguessable job identifier: `job-` and 128 bits from the operating system's random
/// number generator as 32 lowercase hex digits, path-safe and unrelated to the clock,
/// the process or any other job.
///
/// # Errors
///
/// [`JobError::IdUnavailable`] when the operating system yields no random bytes.
fn random_id() -> Result<String, JobError> {
    let bytes = <[u8; 16]>::try_generate().map_err(|_error| JobError::IdUnavailable)?;
    Ok(format!("job-{:032x}", u128::from_be_bytes(bytes)))
}
