//! Catalog grammar contracts for protected CLI templates.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "tests fail through assertions and are not rendered API documentation"
)]
mod tests {
    use core::{error::Error, str::FromStr as _};

    use kcc_app::workflow::CliCommand as ValidatedCli;
    use kcc_catalog::Catalog;
    use kcc_rci::version::FirmwareVersion;
    use secrecy::SecretString;

    /// Context identifiers and trailing identity selectors follow the documented grammar.
    #[test]
    fn contextual_secret_templates_follow_synopsis() -> Result<(), Box<dyn Error>> {
        let catalog =
            Catalog::for_firmware_and_model(FirmwareVersion::from_str("5.1.0")?, Some("KN-1811"))?;
        for (path, argument, template) in [
            ("crypto ike key", "psk", "crypto ike key office {/psk} any"),
            (
                "crypto ike key",
                "psk",
                "crypto ike key office {/psk} fqdn vpn.example",
            ),
            (
                "crypto ipsec profile preshared-key",
                "preshare-key",
                "crypto ipsec profile office preshared-key {/preshare-key}",
            ),
            (
                "crypto ipsec profile xauth-password",
                "password",
                "crypto ipsec profile office xauth-password {/password}",
            ),
            (
                "interface wireguard peer preshared-key",
                "preshared-key",
                "interface Wireguard0 wireguard peer publickey preshared-key {/preshared-key}",
            ),
        ] {
            let request = catalog
                .validate_secret(path, argument, SecretString::from("dummy credential"))
                .map_err(|_issues| "secret fixture rejected")?;
            let command = ValidatedCli::from_template(request, template)?;
            let wire = command.expose_for_send()?;
            assert!(
                wire.contains("\"dummy credential\""),
                "secret is quoted in its argument slot"
            );
        }
        Ok(())
    }

    /// Equality covers the line and the template flag as well as the validated request.
    #[test]
    fn equality_compares_every_field() -> Result<(), Box<dyn Error>> {
        let catalog =
            Catalog::for_firmware_and_model(FirmwareVersion::from_str("5.1.0")?, Some("KN-1811"))?;
        let request = catalog
            .validate_secret(
                "crypto ike key",
                "psk",
                SecretString::from("dummy credential"),
            )
            .map_err(|_issues| "secret fixture rejected")?;
        let line = "crypto ike key office {/psk} any";
        let template = ValidatedCli::from_template(request.clone(), line)?;
        let literal = ValidatedCli::new(line.to_owned(), request.clone());
        let other = ValidatedCli::new("crypto ike key branch {/psk} any".to_owned(), request);
        assert_ne!(template, literal, "the template flag makes a difference");
        assert_ne!(literal, other, "the line makes a difference");
        assert_eq!(literal, literal.clone());
        Ok(())
    }

    /// A valid secret body cannot authorize a different command, slot, or extra argument.
    #[test]
    fn secret_templates_reject_wrong_positions_and_unknown_tokens() -> Result<(), Box<dyn Error>> {
        let catalog =
            Catalog::for_firmware_and_model(FirmwareVersion::from_str("5.1.0")?, Some("KN-1811"))?;
        let request = catalog
            .validate_secret(
                "crypto ike key",
                "psk",
                SecretString::from("dummy credential"),
            )
            .map_err(|_issues| "secret fixture rejected")?;
        for template in [
            "crypto ike key {/psk} office any",
            "crypto ike key office {/psk}",
            "crypto ike key office {/psk} arbitrary vpn.example",
            "crypto ike key office {/psk} any extra",
            "crypto ike key office {/psk} any\nsystem reboot",
            "crypto ike key office {/psk} any;system reboot",
            "crypto ike key office {/psk} any\t",
            "crypto ike key office {/psk} {/psk}",
            "crypto ike key office literal any",
            "crypto ike key office {/unknown} any",
            "crypto ike key office$ {/psk} any",
        ] {
            assert!(
                ValidatedCli::from_template(request.clone(), template).is_err(),
                "invalid grammar must be refused"
            );
        }
        Ok(())
    }

    /// Explicit secret ownership cannot turn an ordinary name into a catalog secret slot.
    #[test]
    fn ordinary_arguments_cannot_be_secret_placeholders() -> Result<(), Box<dyn Error>> {
        let catalog =
            Catalog::for_firmware_and_model(FirmwareVersion::from_str("5.1.0")?, Some("KN-1811"))?;
        let request = catalog
            .validate_secret("user", "name", SecretString::from("guest"))
            .map_err(|_issues| "name fixture rejected")?;
        assert!(
            ValidatedCli::from_template(request, "user {/name}").is_err(),
            "ownership is not a secret classification"
        );
        Ok(())
    }
}
