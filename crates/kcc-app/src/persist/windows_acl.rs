//! Protected owner-only DACLs on Windows.
//!
//! The process user becomes the owner and the DACL holds one allow ACE: full
//! file access for OWNER RIGHTS. The DACL is protected, so nothing is inherited
//! from the parent directory. A directory's ACE is also inherited by the
//! entries created inside it.

use core::str::FromStr as _;
use std::{io, path::Path};

use windows_permissions::{
    LocalBox, SecurityDescriptor,
    constants::{SeObjectType, SecurityInformation},
    utilities::current_process_sid,
    wrappers::SetNamedSecurityInfo,
};

use super::{StateError, io_error};

/// Owner-only DACL of a file.
const FILE_DACL: &str = "D:P(A;;FA;;;OW)";
/// Owner-only DACL of a directory, inherited by files and directories inside it.
const DIRECTORY_DACL: &str = "D:P(A;OICI;FA;;;OW)";

/// Makes `path`, an existing file, owner-only.
///
/// # Errors
///
/// [`StateError::Io`] when the process user, the DACL or the update fails.
pub(super) fn restrict_file(path: &Path) -> Result<(), StateError> {
    restrict(path, FILE_DACL)
}

/// Makes `path`, an existing directory, owner-only.
///
/// # Errors
///
/// [`StateError::Io`] when the process user, the DACL or the update fails.
pub(super) fn restrict_directory(path: &Path) -> Result<(), StateError> {
    restrict(path, DIRECTORY_DACL)
}

/// Sets the process user as owner and `sddl`'s DACL as protected DACL of `path`.
///
/// `SetNamedSecurityInfoW` needs the file object type (an unknown type is
/// rejected with `ERROR_INVALID_PARAMETER`) and takes protection only from the
/// `PROTECTED_DACL_SECURITY_INFORMATION` flag, not from the descriptor.
///
/// # Errors
///
/// [`StateError::Io`] when the process user, the DACL or the update fails.
fn restrict(path: &Path, sddl: &str) -> Result<(), StateError> {
    let owner = current_process_sid().map_err(|source| io_error(path, source))?;
    let descriptor =
        LocalBox::<SecurityDescriptor>::from_str(sddl).map_err(|source| io_error(path, source))?;
    let dacl = descriptor
        .dacl()
        .ok_or_else(|| io_error(path, io::Error::other("owner-only DACL was not created")))?;
    SetNamedSecurityInfo(
        path.as_os_str(),
        SeObjectType::SE_FILE_OBJECT,
        SecurityInformation::Owner | SecurityInformation::Dacl | SecurityInformation::ProtectedDacl,
        Some(&owner),
        None,
        Some(dacl),
        None,
    )
    .map_err(|source| io_error(path, source))
}
