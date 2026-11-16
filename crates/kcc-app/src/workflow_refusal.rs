//! Changes a planning layer refused on its own, before or after a write, for a reason that
//! is neither the catalog's nor the router's.

/// Why a planning layer refused a change.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum Refusal {
    /// A value the caller gave cannot be used: not one safe CLI token, outside its pool,
    /// already taken, or naming something the router does not have.
    #[error("the change names a value that cannot be used")]
    InvalidInput,
    /// The confirmation the caller typed does not match what it confirms.
    #[error("the confirmation does not match")]
    ConfirmationMismatch,
    /// The change needs an explicit confirmation the caller did not give.
    #[error("the change needs an explicit confirmation")]
    ConfirmationRequired,
    /// kcc would lose its own access to the router: its login account or its listener.
    #[error("the change would cut kcc off from the router")]
    ProtectedAccount,
    /// The router's state made the change unsafe, or a removal changed more than it named.
    #[error("the router state made the change unsafe")]
    Unsafe,
}
