//! Keenetic Control Center command-line entry point.

#[expect(
    clippy::absolute_paths,
    clippy::print_stderr,
    reason = "the pre-logging privilege refusal must use only explicit stderr and exit APIs"
)]
fn main() {
    if let Err(error) = kcc::privileges::enforce() {
        eprintln!("{error}");
        std::process::exit(77);
    }
    let cli = kcc::cli::Cli::parse_process();
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            use std::io::Write as _;
            drop(writeln!(
                std::io::stderr(),
                "cannot start async runtime: {error}"
            ));
            std::process::exit(1);
        }
    };
    let result = runtime.block_on(async move {
        match cli.command {
            kcc::cli::Command::Serve { config } => kcc::server::run_serve(config).await,
            kcc::cli::Command::Mcp(kcc::cli::McpCommand::Stdio { config }) => {
                kcc::server::run_stdio(config).await
            }
            kcc::cli::Command::Mcp(_) | _ => Err(kcc::server::ServerError::unsupported_command()),
        }
    });
    let outcome = match result {
        Ok(outcome) => outcome,
        Err(error) => {
            use std::io::Write as _;
            drop(writeln!(std::io::stderr(), "{error}"));
            kcc::server::Outcome::Failed
        }
    };
    if outcome != kcc::server::Outcome::Ok {
        std::process::exit(i32::from(outcome.code()));
    }
}
