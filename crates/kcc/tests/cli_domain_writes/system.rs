//! System write command acceptance.

use core::error::Error;

use super::lab::Lab;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hostname_write_exits_zero_and_a_fresh_read_observes_it() -> Result<(), Box<dyn Error>> {
    let lab = Lab::spawn("").await?;

    let write = lab.run(&["--router", "lab-1", "system", "set-hostname", "cli-host"])?;
    let read = lab.json(&["--router", "lab-1", "system", "state"])?;

    assert_eq!(write.code, 0_i32, "{write:?}");
    assert_eq!(
        read.get("hostname").and_then(serde_json::Value::as_str),
        Some("cli-host")
    );
    assert!(
        lab.fake
            .running_config_text()
            .contains("system hostname cli-host")
    );
    lab.shutdown().await?;
    Ok(())
}
