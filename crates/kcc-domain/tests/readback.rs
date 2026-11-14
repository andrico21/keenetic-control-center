//! Domain writes are read back from the router: an acknowledged write the router ignored
//! fails verification naming its field, and an applied write is reported unsaved.

#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests report failures through assertions"
)]

#[path = "readback/access.rs"]
mod access;
#[path = "readback/model.rs"]
mod model;
#[path = "readback/network.rs"]
mod network;
#[path = "readback/storage.rs"]
mod storage;
mod support;
#[path = "readback/system.rs"]
mod system;

use model::Row;
use support::{PROFILES, TestResult};

/// Every table row of every domain.
fn rows() -> impl Iterator<Item = &'static Row> {
    [access::ROWS, network::ROWS, system::ROWS]
        .into_iter()
        .flatten()
}

/// Runs the rows whose fault setting is `silent` on every firmware profile.
async fn run_rows(silent: bool) -> TestResult {
    for row in rows().filter(|row| row.is_silent() == silent) {
        for firmware in PROFILES {
            model::run(row, firmware).await?;
        }
    }
    Ok(())
}

/// A router that acknowledges a write without applying it fails read-back verification.
#[tokio::test]
async fn silent_writes_name_the_failed_field() -> TestResult {
    run_rows(true).await
}

/// Writes the router applies are read back and reported unsaved.
#[tokio::test]
async fn applied_writes_are_read_back() -> TestResult {
    run_rows(false).await
}
