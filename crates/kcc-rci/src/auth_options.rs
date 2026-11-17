//! Authentication policy for one immutable router identity.

use core::{fmt, ops::RangeInclusive};

use secrecy::SecretString;

/// Argon2 memory costs in KiB the ndw4 protocol allows; a local memory ceiling lies here too.
pub const ARGON2_MEMORY_KIB: RangeInclusive<u32> = 8..=0x0004_0000;

/// Argon2 iteration counts the ndw4 protocol allows; a local iteration ceiling lies here too.
pub const ARGON2_ITERATIONS: RangeInclusive<u32> = 1..=64;

/// Password protocol selection. Automatic selection never downgrades after failure.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum Mode {
    /// Prefer ndw4 whenever advertised; otherwise use ndw2.
    #[default]
    Auto,
    /// Require ndw2 explicitly.
    Ndw2,
    /// Require ndw4 explicitly.
    Ndw4,
    /// RFC 7616 authentication through the KeenDNS HTTP Proxy service.
    DigestProxy,
}

/// Per-router authentication settings.
///
/// Access tokens are experimental until the KeeneticOS 5.2 live matrix is verified.
/// A token takes precedence over password authentication. Password fallback requires
/// both credentials and an explicit `token_fallback` opt-in.
#[derive(Clone)]
#[non_exhaustive]
pub struct Options {
    /// Password protocol, used only when no token is active.
    pub mode: Mode,
    /// Experimental `X-NDMA-TKN` credential.
    pub experimental_token: Option<SecretString>,
    /// Permit a rejected token to fall back to configured password credentials.
    pub token_fallback: bool,
    /// Local Argon2 memory ceiling in KiB, within [`ARGON2_MEMORY_KIB`].
    pub max_argon2_memory_kib: u32,
    /// Local Argon2 iteration ceiling, within [`ARGON2_ITERATIONS`].
    pub max_argon2_iterations: u32,
}

impl Default for Options {
    #[inline]
    fn default() -> Self {
        Self {
            mode: Mode::Auto,
            experimental_token: None,
            token_fallback: false,
            max_argon2_memory_kib: *ARGON2_MEMORY_KIB.end(),
            max_argon2_iterations: 16,
        }
    }
}

impl fmt::Debug for Options {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            mode,
            experimental_token: _,
            token_fallback,
            max_argon2_memory_kib,
            max_argon2_iterations,
        } = self;
        f.debug_struct("Options")
            .field("mode", mode)
            .field("experimental_token", &"[REDACTED]")
            .field("token_fallback", token_fallback)
            .field("max_argon2_memory_kib", max_argon2_memory_kib)
            .field("max_argon2_iterations", max_argon2_iterations)
            .finish()
    }
}
