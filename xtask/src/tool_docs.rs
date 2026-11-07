//! `gen-tool-docs`: writes `docs/MCP_TOOLS.md` from the kcc-mcp tool registry.

use std::{fs, io, path::Path, process::Command};

use crate::{Verdict, failure::GateError};

/// The generated document, relative to the repository root.
const TOOLS_MD: &str = "docs/MCP_TOOLS.md";

/// Renders the registry through the `kcc-mcp` `tool-docs` example and writes it.
///
/// # Errors
///
/// Returns [`GateError::Command`] when `cargo run` fails and [`GateError::Write`] when the
/// document cannot be written.
pub(crate) fn generate<W>(root: &Path, out: &mut W) -> Result<Verdict, GateError>
where
    W: io::Write,
{
    let program = "cargo run --quiet --locked -p kcc-mcp --example tool-docs";
    let output = Command::new(env!("CARGO"))
        .args([
            "run",
            "--quiet",
            "--locked",
            "-p",
            "kcc-mcp",
            "--example",
            "tool-docs",
        ])
        .current_dir(root)
        .output()
        .map_err(|source| GateError::Command {
            program: program.to_owned(),
            detail: source.to_string(),
        })?;
    if !output.status.success() {
        return Err(GateError::Command {
            program: program.to_owned(),
            detail: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }
    let path = root.join(TOOLS_MD);
    fs::write(&path, &output.stdout).map_err(|source| GateError::Write {
        path: path.clone(),
        detail: source.to_string(),
    })?;
    writeln!(out, "gen-tool-docs: wrote {TOOLS_MD}")?;
    Ok(Verdict::Pass)
}
