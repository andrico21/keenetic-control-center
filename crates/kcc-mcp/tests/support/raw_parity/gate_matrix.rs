//! Independently reported cases for every raw tool and authorization gate.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "acceptance assertions establish the raw security boundary"
)]

use kcc_app::permissions::{Permission, Role};
use kcc_testkit::{FakeRouter, model::Profile};

use crate::lab::{Lab, TestResult, admin};

/// Drives the production tool with the shared registry-checked matrix's actual input.
// NOT cancel-safe: the fixture owns router and session tasks until shutdown.
async fn refuses(tool: &str, gate: &str) -> TestResult {
    let role = if gate == "forbidden" {
        Role::new(
            "raw-writer".to_owned(),
            [Permission::Read, Permission::Write, Permission::RawRci],
            vec!["*".to_owned()],
        )
    } else {
        admin()
    };
    let lab = Lab::start_with_destructive(
        vec![("lab-1", FakeRouter::builder(Profile::default()).build()?)],
        role,
        gate != "destructive_disabled",
    )
    .await?;
    let input = super::tests::cases(gate != "confirm_required")
        .into_iter()
        .find(|(name, _)| *name == tool)
        .map(|(_, input)| input)
        .ok_or("missing tool matrix case")?;
    let before = lab.requests("lab-1")?;
    let reply = lab.call(tool, input, false).await?;
    assert_eq!(reply.error(), Some(gate), "{tool}");
    assert_eq!(lab.requests("lab-1")?, before, "{tool}: zero requests");
    lab.stop().await
}

/// Gives every matrix cell a separate test result without copying fixture logic.
macro_rules! gate_case {
    ($name:ident, $tool:literal, $gate:literal) => {
        /// Raw tool refusal leaves the router untouched.
        // NOT cancel-safe: the fixture owns router and session tasks until shutdown.
        #[tokio::test]
        async fn $name() -> TestResult {
            refuses($tool, $gate).await
        }
    };
}

gate_case!(execute_role, "kcc_rci_execute", "forbidden");
gate_case!(execute_confirm, "kcc_rci_execute", "confirm_required");
gate_case!(execute_switch, "kcc_rci_execute", "destructive_disabled");
gate_case!(delete_role, "kcc_rci_delete", "forbidden");
gate_case!(delete_confirm, "kcc_rci_delete", "confirm_required");
gate_case!(delete_switch, "kcc_rci_delete", "destructive_disabled");
gate_case!(batch_role, "kcc_rci_batch", "forbidden");
gate_case!(batch_confirm, "kcc_rci_batch", "confirm_required");
gate_case!(batch_switch, "kcc_rci_batch", "destructive_disabled");
gate_case!(cli_role, "kcc_cli_parse", "forbidden");
gate_case!(cli_confirm, "kcc_cli_parse", "confirm_required");
gate_case!(cli_switch, "kcc_cli_parse", "destructive_disabled");
