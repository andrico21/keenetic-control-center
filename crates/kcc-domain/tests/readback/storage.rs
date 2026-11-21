//! Storage eject never claims verified state; it is the documented exclusion.

use kcc_domain::{storage, verification};

use crate::support::{Fixture, PROFILES, TestResult, administrator};

/// Eject is explicitly exempt because it can remove its own readable device surface.
#[tokio::test]
async fn eject_requires_the_documented_action_exclusion() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;
        let plan = storage::plan_eject(
            fixture.context(),
            "router",
            &administrator(),
            "Media0",
            true,
            None,
            false,
        )?;
        verification::require(&storage::change_request(&plan)?)?;
        fixture.shutdown().await?;
    }
    Ok(())
}
