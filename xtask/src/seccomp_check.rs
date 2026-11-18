//! The comparisons of `seccomp gen --check` and `--check-missing`: a freshly rendered
//! profile against the committed one, by allowed syscall name.

use alloc::collections::BTreeSet;
use std::io;

use crate::{Verdict, failure::GateError};

/// The generated profile, relative to the repository root.
pub(crate) const PROFILE: &str = "deploy/podman/seccomp-kcc.json";

/// Every syscall name a profile's rules list; an unparsable profile lists none.
fn profile_names(text: &str) -> BTreeSet<String> {
    let value = serde_json::from_str::<serde_json::Value>(text).unwrap_or_default();
    value
        .get("syscalls")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|rule| rule.get("names")?.as_array().cloned())
        .flatten()
        .filter_map(|name| name.as_str().map(str::to_owned))
        .collect()
}

/// `--check`: passes only when `committed` is byte-identical to `fresh`, and otherwise
/// prints the syscall names only one side allows.
///
/// # Errors
///
/// Report write failures.
pub(crate) fn exact<W>(committed: &str, fresh: &str, out: &mut W) -> Result<Verdict, GateError>
where
    W: io::Write,
{
    if committed == fresh {
        writeln!(out, "seccomp gen --check: {PROFILE} is byte-identical")?;
        return Ok(Verdict::Pass);
    }
    let (old, new) = (profile_names(committed), profile_names(fresh));
    let added: Vec<&str> = new.difference(&old).map(String::as_str).collect();
    let removed: Vec<&str> = old.difference(&new).map(String::as_str).collect();
    writeln!(
        out,
        "seccomp gen --check: {PROFILE} differs; added [{}], removed [{}] (review, then run `cargo xtask seccomp gen`)",
        added.join(", "),
        removed.join(", ")
    )?;
    Ok(Verdict::Fail)
}

/// `--check-missing`: fails only when `fresh` allows a syscall `committed` does not.
/// Names only the committed profile allows vary between traces and pass.
///
/// # Errors
///
/// Report write failures.
pub(crate) fn missing<W>(committed: &str, fresh: &str, out: &mut W) -> Result<Verdict, GateError>
where
    W: io::Write,
{
    let allowed = profile_names(committed);
    let absent: Vec<String> = profile_names(fresh)
        .into_iter()
        .filter(|name| !allowed.contains(name))
        .collect();
    if absent.is_empty() {
        writeln!(
            out,
            "seccomp gen --check-missing: {PROFILE} allows every traced syscall"
        )?;
        return Ok(Verdict::Pass);
    }
    writeln!(
        out,
        "seccomp gen --check-missing: {PROFILE} lacks traced syscalls [{}] (review, then run `cargo xtask seccomp gen`)",
        absent.join(", ")
    )?;
    Ok(Verdict::Fail)
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::error::Error;
    use std::fs;

    use super::PROFILE;
    use crate::{
        Verdict,
        seccomp_gen::{GenMode, generate},
    };

    /// X-13: `--check-missing` fails only when a traced syscall is absent from the
    /// committed profile; a profile with extra names passes.
    #[test]
    fn check_missing_fails_only_on_a_traced_syscall_absent_from_the_profile()
    -> Result<(), Box<dyn Error>> {
        let root = tempfile::tempdir()?;
        let trace_dir = root.path().join("traces");
        let profile = root.path().join(PROFILE);
        fs::create_dir_all(&trace_dir)?;
        fs::create_dir_all(root.path().join("deploy/podman"))?;
        let trace = "1 read(3, \"\", 4) = 0\n1 getsockopt(7, SOL_SOCKET, SO_ERROR, [0], [4]) = 0\n";
        fs::write(trace_dir.join("trace.1"), trace)?;
        let run = |mode| generate(root.path(), Some(&trace_dir), mode, &mut Vec::new());
        assert_eq!(
            run(GenMode::Write)?,
            Verdict::Pass,
            "the baseline profile is written"
        );
        let fresh = fs::read_to_string(&profile)?;
        let with_extra = fresh.replacen("\"getsockopt\"", "\"getsockopt\",\n\"poll\"", 1);
        let without = fresh.replacen("\"getsockopt\"", "\"getpid\"", 1);
        assert!(
            with_extra != fresh && without != fresh,
            "the fixture edits apply"
        );
        fs::write(&profile, &with_extra)?;
        assert_eq!(
            run(GenMode::CheckMissing)?,
            Verdict::Pass,
            "extras are not drift"
        );
        fs::write(&profile, &without)?;
        assert_eq!(
            run(GenMode::CheckMissing)?,
            Verdict::Fail,
            "a traced syscall is missing"
        );
        Ok(())
    }
}
