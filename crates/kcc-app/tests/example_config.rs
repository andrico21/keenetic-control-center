//! The shipped `kcc.example.toml` parses, validates and states the real defaults.

#[cfg(test)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[expect(
    clippy::missing_errors_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use core::error::Error;

    use kcc_app::settings::Config;

    /// The sample config shipped in release archives.
    const EXAMPLE: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../kcc.example.toml"
    ));

    #[test]
    fn example_config_parses_validates_and_matches_defaults() -> Result<(), Box<dyn Error>> {
        let example = Config::from_toml_str(EXAMPLE)?;
        example.validate()?;
        let defaults = Config::default();

        assert_eq!(
            example.server.listen_addr, defaults.server.listen_addr,
            "server.listen_addr"
        );
        assert_eq!(
            example.server.listen_port, defaults.server.listen_port,
            "server.listen_port"
        );
        assert_eq!(
            example.observability.log_level, defaults.observability.log_level,
            "observability.log_level"
        );
        assert_eq!(
            example.observability.log_format, defaults.observability.log_format,
            "observability.log_format"
        );
        assert_eq!(example.web, defaults.web, "[web]");
        assert_eq!(example.mcp, defaults.mcp, "[mcp]");
        assert_eq!(example.outbound, defaults.outbound, "[outbound]");
        assert_eq!(example.state, defaults.state, "[state]");
        assert_eq!(example.backups, defaults.backups, "[backups]");
        assert_eq!(example.audit, defaults.audit, "[audit]");
        assert_eq!(example.cli, defaults.cli, "[cli]");
        assert_eq!(example.privacy, defaults.privacy, "[privacy]");
        assert_eq!(example.metrics, defaults.metrics, "[metrics]");
        assert_eq!(example.logs, defaults.logs, "[logs]");
        assert_eq!(example.notify, defaults.notify, "[notify]");
        assert!(example.routers.is_empty(), "the sample defines no router");
        Ok(())
    }
}
