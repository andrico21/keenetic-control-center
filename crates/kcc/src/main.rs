//! Keenetic Control Center command-line entry point.

use std::{
    io::{self, Write as _},
    process::ExitCode,
};

use kcc::cli::{args::Cli, entry};
use tokio::runtime::Builder;

#[expect(
    clippy::absolute_paths,
    reason = "the privilege floor stays textually first and fully qualified for the source guard"
)]
fn main() -> ExitCode {
    if let Err(error) = kcc::privileges::enforce() {
        drop(writeln!(io::stderr(), "{error}"));
        return ExitCode::from(77);
    }
    let cli = match Cli::try_parse_process() {
        Ok(cli) => cli,
        Err(error) => {
            drop(error.print());
            return ExitCode::from(u8::try_from(error.exit_code()).unwrap_or(2));
        }
    };
    let runtime = match Builder::new_multi_thread().enable_all().build() {
        Ok(runtime) => runtime,
        Err(error) => {
            drop(writeln!(
                io::stderr(),
                "cannot start async runtime: {error}"
            ));
            return ExitCode::from(1);
        }
    };
    ExitCode::from(runtime.block_on(entry::run(cli)))
}
