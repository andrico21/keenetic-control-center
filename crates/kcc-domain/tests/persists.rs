//! Operations the router persists immediately, flagged from the catalog.

#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests use assertions and a boxed error result"
)]

mod support;

use core::str::FromStr as _;

use kcc_app::permissions::Permission;
use kcc_catalog::{Catalog, HttpMethod, Risk};
use kcc_domain::{ChangeOp, DomainId, registry};
use kcc_rci::version::FirmwareVersion;
use serde_json::json;

use crate::support::{PROFILES, TestResult};

#[test]
fn plans_and_operations_take_the_flag_from_the_catalog() -> TestResult {
    for firmware in PROFILES {
        let catalog =
            Catalog::for_firmware_and_model(FirmwareVersion::from_str(firmware.title())?, None)?;
        let country = catalog
            .validate(
                "system country",
                HttpMethod::Post,
                &json!({"country": "DE"}),
            )
            .map_err(|_issues| "system country refused")?;
        let plan = ChangeOp::new(
            vec![country],
            Vec::new(),
            Risk::Write,
            Permission::Write,
            false,
        );
        assert!(plan.persists(), "a catalog-flagged request marks its plan");
        let description = catalog
            .validate(
                "interface description",
                HttpMethod::Post,
                &json!({"description": "lan"}),
            )
            .map_err(|_issues| "description refused")?;
        let ordinary = ChangeOp::new(
            vec![description],
            Vec::new(),
            Risk::Write,
            Permission::Write,
            false,
        );
        assert!(!ordinary.persists(), "an ordinary plan is not flagged");
        let interfaces = registry()
            .iter()
            .find(|domain| domain.id == DomainId::Interfaces)
            .ok_or("interfaces domain absent")?;
        let operation = interfaces
            .write_ops
            .iter()
            .find(|operation| operation.catalog_path == "interface description")
            .ok_or("description operation absent")?;
        assert!(!operation.persists_immediately_on(&catalog));
    }
    Ok(())
}
