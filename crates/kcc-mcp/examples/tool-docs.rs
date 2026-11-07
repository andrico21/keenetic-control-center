//! Prints the MCP tool reference as Markdown; `cargo xtask gen-tool-docs` writes it to
//! `docs/MCP_TOOLS.md`.

use std::io::{self, Write as _};

use kcc_mcp::registry::docs::markdown;

fn main() -> io::Result<()> {
    io::stdout().write_all(markdown().as_bytes())
}
