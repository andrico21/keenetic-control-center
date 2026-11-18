//! `seccomp trace`: runs the static musl `kcc` natively under `strace` while
//! `deploy/podman/e2e.sh` drives every I/O path, and reads the traced syscall names back.

use alloc::collections::BTreeSet;
use std::{
    env, fs, io,
    path::{Path, PathBuf},
    process::Command,
};

use crate::{Verdict, failure::GateError};

/// The e2e driver, relative to the repository root.
const E2E: &str = "deploy/podman/e2e.sh";

/// The cargo target directory: `CARGO_TARGET_DIR` or `<root>/target`.
fn target_dir(root: &Path) -> PathBuf {
    env::var_os("CARGO_TARGET_DIR").map_or_else(|| root.join("target"), PathBuf::from)
}

/// The default trace directory, `<target>/seccomp-trace`.
pub(crate) fn default_trace_dir(root: &Path) -> PathBuf {
    target_dir(root).join("seccomp-trace")
}

/// The release musl binary of the host architecture.
fn default_binary(root: &Path) -> PathBuf {
    target_dir(root)
        .join(format!("{}-unknown-linux-musl", env::consts::ARCH))
        .join("release")
        .join("kcc")
}

/// Fails unless `binary` is a static executable: a dynamic ELF names its loader.
///
/// # Errors
///
/// [`GateError::Read`] when the file cannot be read, [`GateError::Command`] when it is
/// dynamically linked.
fn ensure_static(binary: &Path) -> Result<(), GateError> {
    let bytes = fs::read(binary).map_err(|source| GateError::Read {
        path: binary.to_owned(),
        source,
    })?;
    let dynamic = [b"ld-linux".as_slice(), b"ld-musl".as_slice()]
        .iter()
        .any(|loader| bytes.windows(loader.len()).any(|window| window == *loader));
    if dynamic {
        return Err(GateError::Command {
            program: binary.display().to_string(),
            detail: "the binary is dynamically linked; trace the static musl build".to_owned(),
        });
    }
    Ok(())
}

/// Runs the e2e driver natively under `strace -f -qq -ff -o <dir>/trace`.
///
/// # Errors
///
/// [`GateError::Command`] when `strace` or the driver fails, [`GateError::Write`] when the
/// trace directory cannot be prepared.
#[expect(
    clippy::disallowed_methods,
    reason = "xtask runs the e2e driver script with bash under strace to record the traced syscalls"
)]
pub(crate) fn trace<W>(
    root: &Path,
    binary: Option<&Path>,
    dir: Option<&Path>,
    out: &mut W,
) -> Result<Verdict, GateError>
where
    W: io::Write,
{
    let binary_path = binary.map_or_else(|| default_binary(root), Path::to_path_buf);
    let dir_path = dir.map_or_else(|| default_trace_dir(root), Path::to_path_buf);
    let (binary_file, trace_dir) = (binary_path.as_path(), dir_path.as_path());
    ensure_static(binary_file)?;
    probe("strace", &["-V"])?;
    if trace_dir.exists() {
        fs::remove_dir_all(trace_dir).map_err(|source| GateError::Write {
            path: trace_dir.to_owned(),
            detail: source.to_string(),
        })?;
    }
    fs::create_dir_all(trace_dir).map_err(|source| GateError::Write {
        path: trace_dir.to_owned(),
        detail: source.to_string(),
    })?;
    let program = format!("bash {E2E} --native {}", binary_file.display());
    let output = Command::new("bash")
        .arg(root.join(E2E))
        .arg("--native")
        .arg(binary_file)
        .arg("--trace-dir")
        .arg(trace_dir)
        .current_dir(root)
        .output()
        .map_err(|source| GateError::Command {
            program: program.clone(),
            detail: source.to_string(),
        })?;
    out.write_all(&output.stdout)?;
    if !output.status.success() {
        return Err(GateError::Command {
            program,
            detail: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }
    let names = read_traces(trace_dir)?;
    writeln!(
        out,
        "seccomp trace: {} distinct syscalls traced into {}",
        names.len(),
        trace_dir.display()
    )?;
    Ok(Verdict::Pass)
}

/// Fails when `program` cannot be run.
///
/// # Errors
///
/// [`GateError::Command`] naming the missing tool.
#[expect(
    clippy::disallowed_methods,
    reason = "xtask probes that a required external tool (strace) can run"
)]
fn probe(program: &str, args: &[&str]) -> Result<(), GateError> {
    let status = Command::new(program)
        .args(args)
        .output()
        .map_err(|source| GateError::Command {
            program: program.to_owned(),
            detail: format!("{source}; install it (see deploy/podman/README.md)"),
        })?
        .status;
    if status.success() {
        Ok(())
    } else {
        Err(GateError::Command {
            program: program.to_owned(),
            detail: format!("exited with {status}"),
        })
    }
}

/// The union of syscall names in every `trace*` file of `dir`.
///
/// # Errors
///
/// [`GateError::Read`] when the directory or a trace cannot be read, or holds no trace.
pub(crate) fn read_traces(dir: &Path) -> Result<BTreeSet<String>, GateError> {
    let read_error = |source| GateError::Read {
        path: dir.to_owned(),
        source,
    };
    let mut names = BTreeSet::new();
    let mut files = 0_usize;
    for entry in fs::read_dir(dir).map_err(read_error)? {
        let path = entry.map_err(read_error)?.path();
        let is_trace = path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("trace"));
        if !is_trace {
            continue;
        }
        files = files.saturating_add(1);
        let text = fs::read_to_string(&path).map_err(|source| GateError::Read {
            path: path.clone(),
            source,
        })?;
        names.extend(text.lines().filter_map(syscall_name).map(str::to_owned));
    }
    if files == 0 {
        return Err(read_error(io::Error::new(
            io::ErrorKind::NotFound,
            "no trace* file; run `cargo xtask seccomp trace` first",
        )));
    }
    Ok(names)
}

/// The syscall a strace line records: `[pid ]name(args) = result`. Signal (`---`), exit
/// (`+++`) and resumption (`<...`) lines carry none.
fn syscall_name(line: &str) -> Option<&str> {
    let call = line
        .trim_start_matches(|byte: char| byte.is_ascii_digit())
        .trim_start();
    let end = call.find('(')?;
    let name = call.get(..end)?;
    let valid = !name.is_empty()
        && name
            .chars()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == '_');
    valid.then_some(name)
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use super::syscall_name;

    #[test]
    fn strace_lines_yield_their_syscall() {
        let cases = [
            ("openat(AT_FDCWD, \"/etc/hosts\", O_RDONLY) = 3", Some("openat")),
            ("12345 getsockopt(7, SOL_SOCKET, SO_ERROR, [0], [4]) = 0", Some("getsockopt")),
            ("restart_syscall(<... resumed interrupted call>) = 0", Some("restart_syscall")),
            ("exit_group(0)                           = ?", Some("exit_group")),
            ("--- SIGTERM {si_signo=SIGTERM} ---", None),
            ("+++ exited with 0 +++", None),
            ("<... futex resumed>) = 0", None),
        ];
        for (line, expected) in cases {
            assert_eq!(syscall_name(line), expected, "{line}");
        }
    }
}
