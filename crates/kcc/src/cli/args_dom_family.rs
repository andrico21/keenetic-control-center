//! A curated domain's command family: its first commands and the writes added beside
//! them, merged into one subcommand list.

use clap::Subcommand;

/// The commands of one curated domain.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum Family<B, W>
where
    B: Subcommand,
    W: Subcommand,
{
    /// The domain's reads and first writes.
    #[command(flatten)]
    Base(B),
    /// The domain's remaining writes.
    #[command(flatten)]
    Writes(W),
}
