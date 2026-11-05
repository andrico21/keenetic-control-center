//! `kcc-fake-router`: serves a [`kcc_testkit::FakeRouter`] on a TCP address.

use core::{error::Error, net::SocketAddr};
use std::{fs, io, path::PathBuf, process::ExitCode};

use clap::Parser;
use kcc_testkit::{
    DEFAULT_LOGIN, FakeRouter,
    model::{Firmware, Model, Profile},
};
use tokio::{net::TcpListener, runtime::Builder, signal};
use zeroize::Zeroizing;

/// Command-line arguments.
#[derive(Debug, Parser)]
#[command(about = "Fake Keenetic/Netcraze router for tests")]
struct Args {
    /// Model id: KN-1811, KN-1010, KN-3810 or NC-3013.
    #[arg(long)]
    model: Model,
    /// Firmware line: 5.1, 5.0 or 4.3.
    #[arg(long, default_value = "5.1")]
    firmware: Firmware,
    /// Address to listen on, e.g. 127.0.0.1:18080.
    #[arg(long)]
    bind: SocketAddr,
    /// File holding the user's password (trailing newline ignored).
    #[arg(long)]
    password_file: PathBuf,
    /// Login of the user.
    #[arg(long, default_value = DEFAULT_LOGIN)]
    login: String,
}

/// Serves `router` on `bind` until Ctrl-C.
///
/// # Errors
///
/// Binding or serving I/O errors.
// NOT cancel-safe: runs the server until the shutdown signal; meant as the top-level task.
async fn serve(router: FakeRouter, bind: SocketAddr) -> io::Result<()> {
    let listener = TcpListener::bind(bind).await?;
    tracing::info!(
        addr = %listener.local_addr()?,
        cookie = router.cookie_name(),
        realm = router.realm(),
        "fake router listening"
    );
    axum::serve(listener, router.router())
        .with_graceful_shutdown(async {
            if let Err(error) = signal::ctrl_c().await {
                tracing::error!(%error, "cannot listen for Ctrl-C");
            }
        })
        .await
}

/// Reads the password file, builds the profile's router and serves it.
///
/// # Errors
///
/// An unreadable password file, an unsupported profile, or a serving error.
fn run(args: Args) -> Result<(), Box<dyn Error>> {
    let raw = Zeroizing::new(fs::read_to_string(&args.password_file)?);
    let password = Zeroizing::new(raw.trim_end_matches(['\r', '\n']).to_owned());
    let profile = Profile::new(args.model, args.firmware)?;
    let router = FakeRouter::builder(profile)
        .user(args.login, password.as_str(), ["cli", "http-proxy"])
        .build()?;
    Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(serve(router, args.bind))?;
    Ok(())
}

fn main() -> ExitCode {
    tracing_subscriber::fmt().with_writer(io::stderr).init();
    match run(Args::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(%error, "kcc-fake-router failed");
            ExitCode::FAILURE
        }
    }
}
