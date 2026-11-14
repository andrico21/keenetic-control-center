//! Running a toolchain program and capturing its standard output.

use std::process::Command;

use crate::failure::GateError;

/// Runs `program args` and returns its stdout.
///
/// # Errors
///
/// Returns [`GateError::Command`] when it cannot start, exits non-zero or prints
/// non-UTF-8.
pub(crate) fn stdout_of(program: &str, args: &[&str]) -> Result<String, GateError> {
    let line = format!("{program} {}", args.join(" "));
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|err| GateError::Command {
            program: line.clone(),
            detail: err.to_string(),
        })?;
    if !output.status.success() {
        return Err(GateError::Command {
            program: line,
            detail: format!("exited with {}", output.status),
        });
    }
    String::from_utf8(output.stdout).map_err(|err| GateError::Command {
        program: line,
        detail: err.to_string(),
    })
}
