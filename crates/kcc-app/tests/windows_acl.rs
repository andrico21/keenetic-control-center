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

    /// Diagnostic probes of DACL variants; they assert nothing about the variant.
    ///
    /// Each applies one variant to a fresh file and directory and writes the Win32
    /// outcome and the SDDL before and after to stderr directly, so libtest does not
    /// capture it. They are removed once the Windows behaviour of every variant is known.
    mod probes {
        use std::{
            fs,
            io::{self, Write as _},
            path::Path,
        };

        use tempfile::TempDir;
        use windows_permissions::{
            LocalBox, SecurityDescriptor, WindowsSecure as _,
            constants::{SeObjectType, SecurityInformation},
            utilities::current_process_sid,
            wrappers::SetNamedSecurityInfo,
        };

        use super::{TestResult, describe};

        /// How a probe applies its DACL.
        #[derive(Clone, Copy)]
        enum Call {
            /// `WindowsSecure::set_dacl` on the path, as kcc did before.
            UnknownObjectType,
            /// `SetNamedSecurityInfoW` for a file object.
            FileObject {
                /// The security information flags.
                info: SecurityInformation,
                /// Also sets the process user as owner.
                set_owner: bool,
            },
        }

        /// Applies `sddl`'s DACL to `path` with `call`; the outcome names the failing step.
        fn apply(call: Call, sddl: &str, path: &Path) -> String {
            let descriptor = match sddl.parse::<LocalBox<SecurityDescriptor>>() {
                Ok(descriptor) => descriptor,
                Err(error) => return format!("parse the descriptor failed: {error}"),
            };
            let Some(dacl) = descriptor.dacl() else {
                return "the descriptor has no DACL".to_owned();
            };
            let outcome = match call {
                Call::UnknownObjectType => path.as_os_str().to_owned().set_dacl(dacl),
                Call::FileObject { info, set_owner } => {
                    let owner = if set_owner {
                        match current_process_sid() {
                            Ok(owner) => Some(owner),
                            Err(error) => return format!("read the process user failed: {error}"),
                        }
                    } else {
                        None
                    };
                    SetNamedSecurityInfo(
                        path.as_os_str(),
                        SeObjectType::SE_FILE_OBJECT,
                        info,
                        owner.as_deref(),
                        None,
                        Some(dacl),
                        None,
                    )
                }
            };
            outcome.map_or_else(
                |error| format!("set the DACL failed: {error}"),
                |()| "ok".to_owned(),
            )
        }

        /// Runs one variant on a fresh file, then on its fresh parent directory.
        fn run(label: &str, call: Call, sddl: &str) -> TestResult {
            let temp = TempDir::new()?;
            let dir = temp.path().join("probe");
            fs::create_dir_all(&dir)?;
            let file = dir.join("probe.json");
            fs::write(&file, b"{}")?;
            let mut stderr = io::stderr().lock();
            for path in [&file, &dir] {
                let before = describe(path);
                let outcome = apply(call, sddl, path);
                let after = describe(path);
                writeln!(
                    stderr,
                    "kcc-probe {label} {}: before={before} set={outcome} after={after}",
                    path.display()
                )?;
            }
            Ok(())
        }

        /// Probe: the pre-fix call (unknown object type); expected to report os error 87.
        #[test]
        fn unknown_object_type() -> TestResult {
            run(
                "unknown-object-type",
                Call::UnknownObjectType,
                "D:P(A;;GA;;;OW)",
            )
        }

        /// Probe: file object type without the protection flag; shows whether inherited
        /// ACEs (flag `ID`) stay next to the new ACE.
        #[test]
        fn file_object_unprotected() -> TestResult {
            let call = Call::FileObject {
                info: SecurityInformation::Dacl,
                set_owner: false,
            };
            run("file-object-unprotected", call, "D:P(A;;GA;;;OW)")
        }

        /// Probe: the pre-fix descriptor (`GA`) protected, owner unchanged; shows whether
        /// `GENERIC_ALL` is stored mapped (`FA`) or unmapped (`GA`).
        #[test]
        fn protected_generic_all() -> TestResult {
            let call = Call::FileObject {
                info: SecurityInformation::Dacl | SecurityInformation::ProtectedDacl,
                set_owner: false,
            };
            run("protected-generic-all", call, "D:P(A;;GA;;;OW)")
        }

        /// Probe: the product DACL without the owner change; the fallback should setting
        /// the owner fail.
        #[test]
        fn protected_without_owner() -> TestResult {
            let call = Call::FileObject {
                info: SecurityInformation::Dacl | SecurityInformation::ProtectedDacl,
                set_owner: false,
            };
            run("protected-without-owner", call, "D:P(A;;FA;;;OW)")
        }

        /// Probe: the product call (owner, protected DACL, `FA` for OWNER RIGHTS); shows the
        /// default owner and DACL before and the result after.
        #[test]
        fn product_call() -> TestResult {
            let call = Call::FileObject {
                info: SecurityInformation::Owner
                    | SecurityInformation::Dacl
                    | SecurityInformation::ProtectedDacl,
                set_owner: true,
            };
            run("product", call, "D:P(A;;FA;;;OW)")
        }
    }
}
