//! Curated management changes and the roles that may make them.

use kcc_app::permissions::Permission;

use super::{TestResult, add_role, commands_after, edges, lab};

/// Curated Wi-Fi and segment management changes run inside the recovery timer for every
/// role that may write, and a reader is refused before any router command.
// NOT cancel-safe: the fixture owns router tasks and child processes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn curated_wifi_and_segment_changes_bracket_writers_both_modes() -> TestResult {
    for role in ["reader", "operator", "writer"] {
        for mode in ["router", "extender"] {
            let (env, handle, _address) = lab(mode, role).await?;
            match role {
                "reader" => add_role(&env, role, &[Permission::Read])?,
                "writer" => add_role(&env, role, &[Permission::Read, Permission::Write])?,
                _ => {}
            }
            for input in [
                vec![
                    "--yes",
                    "wifi",
                    "enable",
                    "--ap",
                    "WifiMaster0/AccessPoint0",
                    "off",
                ],
                vec![
                    "--yes",
                    "segments",
                    "create",
                    "7",
                    "--vlan",
                    "7",
                    "--address",
                    "198.51.100.1",
                    "--mask",
                    "255.255.255.0",
                    "--dhcp-begin",
                    "198.51.100.10",
                    "--dhcp-end",
                    "198.51.100.50",
                    "--access-point",
                    "WifiMaster0/AccessPoint0",
                ],
            ] {
                let before = handle.request_log().len();
                let run = env.kcc(&input)?;
                let commands = commands_after(&handle, before);
                if role == "reader" {
                    assert_eq!(run.code, 10_i32, "{role} {mode} {input:?}: {run:?}");
                    assert!(commands.is_empty(), "{input:?}: {commands:?}");
                } else {
                    assert_eq!(run.code, 0_i32, "{role} {mode} {input:?}: {run:?}");
                    let (arm, disarm) = edges(mode);
                    assert_eq!(commands.first().map(String::as_str), Some(arm));
                    assert_eq!(commands.last().map(String::as_str), Some(disarm));
                }
            }
            handle.shutdown().await?;
        }
    }
    Ok(())
}
