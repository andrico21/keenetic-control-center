//! Structural parity between generated CLI grammar and name-keyed raw JSON.

use core::{error::Error, str::FromStr as _};

use kcc_rci::version::FirmwareVersion;

use crate::{Catalog, HttpMethod, RawAuthorization};

/// Every generated spelling accepted by both validators has one risk verdict.
#[test]
fn cli_and_structured_spellings_have_identical_risk() -> Result<(), Box<dyn Error>> {
    for version in ["4.3.0", "5.0.0", "5.1.0"] {
        let catalog = Catalog::for_firmware_and_model(FirmwareVersion::from_str(version)?, None)?;
        let mut compared = 0_usize;
        for (line, body) in catalog.raw_parity_cases() {
            let Ok(cli) = catalog.validate_cli(&line, RawAuthorization::default()) else {
                continue;
            };
            let Ok(structured) = catalog.validate("", HttpMethod::Post, &body) else {
                continue;
            };
            assert_eq!(cli.risk, structured.risk, "{version}: {line}: {body}");
            assert_eq!(
                cli.contains_management(),
                structured.contains_management(),
                "{version}: {line}: {body}"
            );
            compared = compared.saturating_add(1);
        }
        assert!(compared != 0, "{version}: no shared generated spellings");
    }
    Ok(())
}
