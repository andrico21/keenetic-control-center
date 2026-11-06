//! Prints the metric catalogue as Markdown; `cargo xtask gen-metric-docs` writes it to
//! `docs/METRICS.md`.

use std::io::{self, Write as _};

use kcc_telemetry::metrics::docs::markdown;

fn main() -> io::Result<()> {
    io::stdout().write_all(markdown().as_bytes())
}
