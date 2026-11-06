//! Public write request redaction properties.

#[cfg(test)]
mod tests {
    use core::str::FromStr as _;

    use kcc_app::{
        permissions::Permission,
        workflow::{
            BatchChangeRequest, BatchItem, ChangeRequest, CliChangeRequest, CliCommand,
            DeleteRequest, TerminalCliChangeRequest,
        },
    };
    use kcc_catalog::{Catalog, HttpMethod};
    use kcc_rci::version::FirmwareVersion;
    use proptest::{
        prelude::proptest,
        test_runner::{Config, RngSeed, TestCaseError},
    };
    use serde_json::json;

    proptest! {
        #![proptest_config(Config { cases: 256, rng_seed: RngSeed::Fixed(29), ..Config::default() })]
        /// Every public request keeps its printable representation independent of secret input.
        #[test]
        fn public_requests_redact_secrets(secret in "[^\\p{Cc}]{1,64}") {
            let catalog = Catalog::for_firmware_and_model(FirmwareVersion::from_str("5.1.0")?, Some("KN-1811"))?;
            let mut projections = Vec::new();
            for input in [secret.as_str(), "replacement-fixture"] {
                let body = json!({"password":input});
                let validated = catalog.validate("user password plain", HttpMethod::Post, &body)
                    .map_err(|_issues| TestCaseError::fail("valid secret refused"))?;
                let cli = CliCommand::from_template(validated.clone(), "user guest password plain {/password}")?;
                let cli_request = CliChangeRequest::new(vec![cli.clone()], Vec::new(), Permission::Write, json!({"detail":input}));
                let terminal = TerminalCliChangeRequest::new(vec![cli.clone()], Permission::Write, json!({"detail":input}));
                let change = ChangeRequest::new("user password plain".to_owned(), vec!["user".to_owned()], body.clone(), Vec::new(), Permission::Write, json!({"detail":input}));
                let delete = DeleteRequest::new("user password plain".to_owned(), vec!["user".to_owned()], body, Vec::new(), Permission::Write, json!({"detail":input}));
                let item = BatchItem::new(json!({"user":{"password":{"plain":{"password":input}}}}), validated.clone());
                let batch = BatchChangeRequest::new(vec![item.clone()], Vec::new(), Permission::Write, json!({"detail":input}));
                projections.push((
                    format!("{validated:?} {cli:?} {cli_request:?} {terminal:?} {change:?} {delete:?} {item:?} {batch:?}"),
                    serde_json::to_value((&validated, &cli, &cli_request, &terminal, &change, &delete, &item, &batch))?
                ));
            }
            assert!(matches!(projections.as_slice(), [first, second] if first == second), "printable requests must not depend on secret values");
        }
    }
}
