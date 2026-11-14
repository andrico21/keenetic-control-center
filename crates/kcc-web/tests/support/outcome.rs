//! How a test or a test helper ends.

use core::error::Error;

/// Fallible test result.
pub(crate) type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;
