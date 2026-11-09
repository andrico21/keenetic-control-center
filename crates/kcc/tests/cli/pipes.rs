//! Output into a closed pipe, as in `kcc completions bash | head`, ends quietly.

use std::io::pipe;

use super::support::{Env, TestResult};

#[test]
fn closed_stdout_ends_with_status_zero_and_no_message() -> TestResult {
    let env = Env::new("")?;
    let config = env.path("kcc.toml");
    let config_arg = config.to_str().ok_or("non-UTF-8 path")?;
    for args in [
        &["completions", "bash"][..],
        &["--config", config_arg, "--json", "router", "list"][..],
    ] {
        let (reader, writer) = pipe()?;
        drop(reader);
        let output = env.command(args).stdout(writer).output()?;
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(0_i32), "{args:?}: {stderr}");
        assert!(stderr.is_empty(), "{args:?} printed: {stderr}");
    }
    Ok(())
}
