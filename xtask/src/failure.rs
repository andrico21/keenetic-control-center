//! The error type shared by every gate.

use core::{error::Error, fmt};
use std::{io, path::PathBuf};

use toml::de;

/// Why a gate could not run to a verdict.
#[derive(Debug)]
pub(crate) enum GateError {
    /// The repository root could not be derived from the xtask manifest directory.
    NoRoot,
    /// Reading a file or directory failed.
    Read {
        /// The path that could not be read.
        path: PathBuf,
        /// The underlying I/O error.
        source: io::Error,
    },
    /// A manifest is not valid TOML.
    Toml {
        /// The manifest path.
        path: PathBuf,
        /// The parse error.
        source: de::Error,
    },
    /// A manifest lacks a required table.
    MissingTable {
        /// The manifest path.
        path: PathBuf,
        /// The dotted key of the missing table.
        key: String,
    },
    /// A subprocess could not be run or did not succeed.
    Command {
        /// The command line, for the message.
        program: String,
        /// What went wrong.
        detail: String,
    },
    /// Writing the report failed.
    Output(io::Error),
}

impl fmt::Display for GateError {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoRoot => f.write_str("cannot derive the repository root; pass --root"),
            Self::Read { path, source } => write!(f, "cannot read {}: {source}", path.display()),
            Self::Toml { path, source } => write!(f, "cannot parse {}: {source}", path.display()),
            Self::MissingTable { path, key } => {
                write!(f, "{} has no [{key}] table", path.display())
            }
            Self::Command { program, detail } => write!(f, "`{program}` failed: {detail}"),
            Self::Output(source) => write!(f, "cannot write the report: {source}"),
        }
    }
}

impl Error for GateError {
    #[inline]
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Read { source, path: _ } | Self::Output(source) => Some(source),
            Self::Toml { source, path: _ } => Some(source),
            Self::NoRoot
            | Self::MissingTable { path: _, key: _ }
            | Self::Command {
                program: _,
                detail: _,
            } => None,
        }
    }
}

impl From<io::Error> for GateError {
    #[inline]
    fn from(source: io::Error) -> Self {
        Self::Output(source)
    }
}
