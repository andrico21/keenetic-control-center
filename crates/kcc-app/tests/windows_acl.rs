//! Owner-only DACLs of state directories and files on Windows, read back from the file system.
#![cfg(windows)]

#[cfg(test)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use core::error::Error;
    use std::path::Path;

    use kcc_app::persist::{create_private_dir, write_atomic};
    use tempfile::TempDir;
    use windows_permissions::{
        LocalBox, SecurityDescriptor, Sid,
        constants::{AceFlags, AceType, SeObjectType, SecurityInformation},
        utilities::current_process_sid,
        wrappers::GetNamedSecurityInfo,
    };

    /// Test result.
    type TestResult = Result<(), Box<dyn Error>>;

    /// `FILE_ALL_ACCESS`.
    const FILE_ALL_ACCESS: u32 = 0x001F_01FF;
    /// The OWNER RIGHTS SID.
    const OWNER_RIGHTS: &str = "S-1-3-4";

    /// Reads the owner and DACL of `path`; the error names the step.
    fn read_back(path: &Path) -> Result<LocalBox<SecurityDescriptor>, String> {
        GetNamedSecurityInfo(
            path.as_os_str(),
            SeObjectType::SE_FILE_OBJECT,
            SecurityInformation::Owner | SecurityInformation::Dacl,
        )
        .map_err(|error| format!("read back the DACL of {}: {error}", path.display()))
    }

    /// The SDDL of the owner and DACL of `path`, or the failure of reading it.
    fn describe(path: &Path) -> String {
        read_back(path)
            .and_then(|descriptor| {
                descriptor
                    .as_sddl()
                    .map_err(|error| format!("render SDDL: {error}"))
            })
            .map_or_else(|error| error, |sddl| sddl.to_string_lossy().into_owned())
    }

    /// Asserts that `path` is owned by the process user and that its protected
    /// DACL holds one ACE: full access for OWNER RIGHTS with the `inherit` flags.
    fn assert_owner_only(path: &Path, inherit: AceFlags) -> TestResult {
        let descriptor = read_back(path)?;
        let sddl = describe(path);
        let user =
            current_process_sid().map_err(|error| format!("read the process user: {error}"))?;
        assert_eq!(descriptor.owner(), Some(&*user), "owner: {sddl}");
        assert!(sddl.contains("D:P"), "the DACL is not protected: {sddl}");
        let dacl = descriptor
            .dacl()
            .ok_or_else(|| format!("no DACL read back: {sddl}"))?;
        assert_eq!(dacl.len(), 1, "exactly one ACE: {sddl}");
        let ace = dacl
            .get_ace(0)
            .ok_or_else(|| format!("ACE 0 missing: {sddl}"))?;
        let owner_rights: LocalBox<Sid> = OWNER_RIGHTS
            .parse()
            .map_err(|error| format!("parse the OWNER RIGHTS SID: {error}"))?;
        assert_eq!(ace.ace_type(), AceType::ACCESS_ALLOWED_ACE_TYPE, "{sddl}");
        assert_eq!(ace.sid(), Some(&*owner_rights), "trustee: {sddl}");
        assert_eq!(ace.mask().bits(), FILE_ALL_ACCESS, "access mask: {sddl}");
        assert_eq!(ace.flags(), inherit, "ACE flags: {sddl}");
        Ok(())
    }

    /// A state directory is owned by the process user, and its protected DACL grants only
    /// OWNER RIGHTS full access, inherited by the entries created inside it.
    #[test]
    fn state_directory_is_owner_only() -> TestResult {
        let temp = TempDir::new()?;
        let dir = temp.path().join("state");
        create_private_dir(&dir).map_err(|error| format!("create_private_dir: {error}"))?;
        assert_owner_only(&dir, AceFlags::ContainerInherit | AceFlags::ObjectInherit)
    }

    /// A state file written atomically keeps the protected owner-only DACL of its
    /// temporary file after the rename, with no inherited ACE.
    #[test]
    fn state_file_is_owner_only() -> TestResult {
        let temp = TempDir::new()?;
        let dir = temp.path().join("state");
        create_private_dir(&dir).map_err(|error| format!("create_private_dir: {error}"))?;
        write_atomic(&dir, "doc.json", b"{}").map_err(|error| format!("write_atomic: {error}"))?;
        assert_owner_only(&dir.join("doc.json"), AceFlags::empty())
    }
}
