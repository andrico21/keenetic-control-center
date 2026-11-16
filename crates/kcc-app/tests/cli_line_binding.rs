//! A CLI command holds only a line that renders the request it was validated as.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "tests fail through assertions and are not rendered API documentation"
)]
mod tests {
    use core::{error::Error, str::FromStr as _};

    use kcc_app::workflow::{CliCommand, SecretCommandError};
    use kcc_catalog::{Catalog, HttpMethod, RawAuthorization, ValidatedRequest};
    use kcc_rci::version::FirmwareVersion;
    use secrecy::SecretString;
    use serde_json::{Value, json};

    /// The 5.1 catalog of a KN-1811.
    fn catalog() -> Result<Catalog, Box<dyn Error>> {
        Ok(Catalog::for_firmware_and_model(
            FirmwareVersion::from_str("5.1.0")?,
            Some("KN-1811"),
        )?)
    }

    /// `body` of `path`, validated.
    fn request(path: &str, body: &Value) -> Result<ValidatedRequest, Box<dyn Error>> {
        catalog()?
            .validate(path, HttpMethod::Post, body)
            .map_err(|issues| format!("{path}: {issues:?}").into())
    }

    /// Whether `line` is refused as a rendering of `validated`.
    fn refused(line: &str, validated: ValidatedRequest) -> bool {
        matches!(
            CliCommand::new(line.to_owned(), validated),
            Err(SecretCommandError::Line)
        )
    }

    /// B-08: a line of another command is refused next to a valid request.
    #[test]
    fn a_line_of_another_command_is_refused() -> Result<(), Box<dyn Error>> {
        let description = request("interface description", &json!({"description": "uplink"}))?;
        assert!(refused("frobnicate gadget", description.clone()));
        assert!(refused("interface Bridge0 mtu 1400", description.clone()));
        assert!(refused(
            "no interface Bridge0 description",
            description.clone()
        ));
        assert!(!refused(
            "interface Bridge0 description uplink",
            description
        ));
        Ok(())
    }

    /// B-08: a literal that differs from the request's value is refused, also as a secret line.
    #[test]
    fn a_literal_other_than_the_validated_value_is_refused() -> Result<(), Box<dyn Error>> {
        let description = request("interface description", &json!({"description": "uplink"}))?;
        assert!(refused(
            "interface Bridge0 description other",
            description.clone()
        ));
        assert!(matches!(
            CliCommand::secret(
                description,
                SecretString::from("interface Bridge0 description other"),
            ),
            Err(SecretCommandError::Line)
        ));
        let address = request(
            "interface ip address",
            &json!({"address": format!("{}.0.2.1", 192_u8), "mask": "255.255.255.0"}),
        )?;
        let line = format!(
            "interface Bridge0 ip address {}.0.2.9 255.255.255.0",
            192_u8
        );
        assert!(refused(&line, address));
        Ok(())
    }

    /// B-08: a quoted word binds its unquoted text; the same text unquoted is two words.
    #[test]
    fn a_quoted_word_is_bound_to_its_text() -> Result<(), Box<dyn Error>> {
        let description = request(
            "interface description",
            &json!({"description": "two words"}),
        )?;
        assert!(!refused(
            r#"interface Bridge0 description "two words""#,
            description.clone()
        ));
        assert!(refused(
            r#"interface Bridge0 description "two""#,
            description.clone()
        ));
        assert!(refused(
            "interface Bridge0 description two words",
            description.clone()
        ));
        assert!(refused(
            "interface Bridge0 description \"two words\"\ninterface Bridge0 down",
            description
        ));
        Ok(())
    }

    /// B-08: a raw request outside the catalog takes only the line it was authorized as.
    #[test]
    fn a_raw_request_takes_only_its_authorized_line() -> Result<(), Box<dyn Error>> {
        let mut authorization = RawAuthorization::default();
        authorization.raw_rci = true;
        authorization.admin_manage_routers = true;
        let raw = catalog()?
            .validate_cli("frobnicate widget", authorization)
            .map_err(|issues| format!("{issues:?}"))?;
        assert!(raw.unvalidated);
        assert!(refused("frobnicate gadget", raw.clone()));
        assert!(refused("frobnicate widget now", raw.clone()));
        assert!(!refused("frobnicate widget", raw));
        Ok(())
    }
}
