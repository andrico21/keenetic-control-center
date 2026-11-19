//! Paths that tests write into a `kcc.toml` parse back unchanged, Windows paths included.

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
    use std::path::{Path, PathBuf};

    use kcc_app::settings::Config;
    use kcc_testkit::toml_text;

    /// A Windows temporary path whose `\U` once started a TOML unicode escape, and one
    /// with quotes and a tab.
    const PATHS: [&str; 2] = [r"C:\Users\runner\a b\.tmpX", "/tmp/it's \"quoted\"\there"];

    /// Each path round-trips through `toml` and through the kcc configuration parser.
    #[test]
    fn paths_round_trip_through_kcc_toml() -> Result<(), Box<dyn Error>> {
        for raw in PATHS {
            let value = toml_text::path(Path::new(raw));
            let table = toml::from_str::<toml::Table>(&format!("path = {value}\n"))?;
            assert_eq!(table.get("path").and_then(toml::Value::as_str), Some(raw));
            let config = Config::from_toml_str(&format!(
                "[[routers]]\nname = \"lab\"\nurl = \"http://198.51.100.1\"\nlogin = \"admin\"\npassword_file = {value}\n"
            ))?;
            let stored = config
                .routers
                .first()
                .and_then(|router| router.password_file.clone());
            assert_eq!(stored, Some(PathBuf::from(raw)));
        }
        Ok(())
    }
}
