//! The raw consoles' forms never print what was typed.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "test code is not rendered API documentation"
)]

use std::process;

use serde_json::json;

use super::{cli::CliForm, rci_check::RciForm};

/// W4-09: the RCI console body and the CLI console line can carry a router password, so
/// neither form's `Debug` output contains them.
#[test]
fn console_forms_debug_omits_the_typed_text() -> Result<(), serde_json::Error> {
    let secret = format!("typed-{}-{}", process::id(), "pass");
    let rci: RciForm = serde_json::from_value(json!({
        "method": "POST",
        "path": "user",
        "body": format!("{{\"name\":\"admin\",\"password\":\"{secret}\"}}"),
    }))?;
    let cli: CliForm = serde_json::from_value(json!({
        "line": format!("user admin password {secret}"),
    }))?;
    let (rci_text, cli_text) = (format!("{rci:?}"), format!("{cli:?}"));
    for text in [&rci_text, &cli_text] {
        assert!(!text.contains(&secret), "Debug printed the secret: {text}");
    }
    assert!(rci_text.contains("POST"), "the method is still shown");
    Ok(())
}
