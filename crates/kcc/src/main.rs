//! Keenetic Control Center command-line entry point.

use core::time::Duration;
use std::{
    env,
    io::{self, Write as _},
    process::ExitCode,
};

use kcc::cli::{args::Cli, entry};
use tokio::runtime::Builder;

/// How long the exit waits for blocking threads still running once the command returned.
///
/// A stdin read that a signal interrupted never returns, and an unbounded wait would keep
/// `kcc mcp stdio` alive after its shutdown.
const BLOCKING_EXIT_WAIT: Duration = Duration::from_secs(1);

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
            let arguments = env::args_os()
                .skip(1)
                .filter_map(|argument| argument.into_string().ok())
                .collect::<Vec<_>>();
            return ExitCode::from(entry::report_parse_error(&error, &arguments));
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
    let code = runtime.block_on(entry::run(cli));
    runtime.shutdown_timeout(BLOCKING_EXIT_WAIT);
    ExitCode::from(code)
}
