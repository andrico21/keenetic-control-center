//! Sortable job identifier allocation.

use core::sync::atomic::{AtomicU64, Ordering};

use chacha20poly1305::aead::Generate as _;

use super::JobError;

/// Process facts that distinguish otherwise simultaneous allocations.
#[derive(Clone, Copy)]
pub(super) struct ProcessIdentity {
    /// Operating-system process identifier.
    process: u32,
    /// Per-process operating-system entropy.
    entropy: [u8; 4],
}

/// Allocates sortable identifiers within one runner process.
pub(super) struct JobIdAllocator {
    /// Process facts shared by every allocation.
    identity: ProcessIdentity,
    /// Process-local allocation sequence.
    next: AtomicU64,
}

impl JobIdAllocator {
    /// Creates an allocator from the current process and operating-system entropy.
    pub(super) fn system() -> Result<Self, JobError> {
        let entropy = <[u8; 4]>::try_generate().map_err(|_error| JobError::IdUnavailable)?;
        Ok(Self::new(ProcessIdentity {
            process: std::process::id(),
            entropy,
        }))
    }

    /// Creates an allocator from explicit process facts.
    pub(super) const fn new(identity: ProcessIdentity) -> Self {
        Self {
            identity,
            next: AtomicU64::new(1),
        }
    }

    /// Creates an allocator from explicit process facts for deterministic verification.
    #[cfg(test)]
    pub(super) const fn for_test(process: u32, entropy: [u8; 4]) -> Self {
        Self::new(ProcessIdentity { process, entropy })
    }

    /// Allocates one identifier at `timestamp`.
    pub(super) fn allocate(&self, timestamp: u64) -> String {
        let sequence = self.next.fetch_add(1, Ordering::Relaxed);
        from_parts(timestamp, self.identity, sequence)
    }
}

/// Builds one path-safe job identifier from process-local allocation facts.
fn from_parts(timestamp: u64, identity: ProcessIdentity, sequence: u64) -> String {
    let entropy = identity
        .entropy
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .concat();
    format!(
        "job-{timestamp:012x}-{:08x}-{entropy}-{sequence:012x}",
        identity.process
    )
}

#[cfg(test)]
mod tests {
    use super::JobIdAllocator;

    #[test]
    #[expect(
        clippy::missing_panics_doc,
        reason = "the assertion is the test contract"
    )]
    fn same_second_allocations_from_different_processes_are_distinct() {
        let first = JobIdAllocator::for_test(41, [7; 4]).allocate(1_800_000_000);
        let second = JobIdAllocator::for_test(42, [7; 4]).allocate(1_800_000_000);

        assert_ne!(first, second);
    }
}
