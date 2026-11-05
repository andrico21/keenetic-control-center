//! `kcc-capture`: captures a router's read-only resources into anonymized fixtures.
//!
//! Only anonymized output is written; raw responses stay in memory. The router serial
//! must be listed in `--allow-serial` before any other resource is read.

use core::error::Error;
use std::{fs, io, path::PathBuf, process::ExitCode};

use clap::Parser;
use kcc_rci::{RouterUrl, capabilities::RouterInfo};
use kcc_testkit::{
    DEFAULT_LOGIN,
    capture::{connect, read_all, render, verify_serial},
};
use secrecy::SecretString;
use tokio::runtime::Builder;
use zeroize::Zeroizing;

/// Command-line arguments.
#[derive(Debug, Parser)]
#[command(about = "Capture anonymized read-only fixtures from a Keenetic/Netcraze router")]
struct Args {
    /// Router origin, e.g. `http://192.168.1.1`.
    #[arg(long)]
    url: String,
    /// Router account.
    #[arg(long, default_value = DEFAULT_LOGIN)]
    login: String,
    /// File holding the password (trailing newline ignored).
    #[arg(long)]
    password_file: PathBuf,
    /// Comma-separated router serials this tool may read.
    #[arg(long, value_delimiter = ',', required = true)]
    allow_serial: Vec<String>,
    /// Fixture root; the capture goes to `<out>/<hw_id>-<title>/`.
    #[arg(long, default_value = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures"))]
    out: PathBuf,
    /// Admit loopback targets (for the fake router).
    #[arg(long)]
    allow_loopback: bool,
}

/// Connects, checks the serial, captures, anonymizes and writes.
///
/// # Errors
///
/// An unreadable password file, a refused or unreachable router, or an I/O error.
// NOT cancel-safe: meant as the top-level task; a cancelled run may leave a partial fixture.
async fn capture(args: Args) -> Result<(), Box<dyn Error>> {
    let raw = Zeroizing::new(fs::read_to_string(&args.password_file)?);
    let password = SecretString::from(raw.trim_end_matches(['\r', '\n']).to_owned());
    let router = args.url.parse::<RouterUrl>()?;
    let connection = connect(router.clone(), args.login, password, args.allow_loopback).await?;
    drop(verify_serial(&connection.client, &args.allow_serial).await?);
    let info = RouterInfo::detect(&connection.session, &router).await?;
    let hw_id = info.hw_id().unwrap_or("unknown").to_owned();
    let title = info
        .version
        .title
        .as_deref()
        .unwrap_or("unknown")
        .to_owned();
    let captured = read_all(&connection).await;
    let rendered = render(&captured, &hw_id, &title);
    let directory = rendered.write(&args.out)?;
    tracing::info!(
        directory = %directory.display(),
        files = rendered.files.len(),
        items = captured.len(),
        "anonymized capture written"
    );
    Ok(())
}

fn main() -> ExitCode {
    tracing_subscriber::fmt().with_writer(io::stderr).init();
    let args = Args::parse();
    let result = Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(Box::<dyn Error>::from)
        .and_then(|runtime| runtime.block_on(capture(args)));
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(%error, "kcc-capture failed");
            ExitCode::FAILURE
        }
    }
}
