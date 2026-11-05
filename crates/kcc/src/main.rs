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
}
