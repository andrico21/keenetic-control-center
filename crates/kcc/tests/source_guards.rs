//! Source-level startup security invariants.

#[cfg(test)]
#[expect(
    clippy::expect_used,
    clippy::missing_panics_doc,
    reason = "source guards fail through test assertions"
)]
mod tests {
    use std::{fs, path::Path};

    #[test]
    fn privilege_enforcement_is_mains_first_statement() {
        let main = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/main.rs"))
            .expect("main source is readable");
        let body = main
            .split_once("fn main() -> ExitCode {")
            .map(|(_, body)| body.trim_start())
            .expect("main function exists");
        assert!(
            body.starts_with("if let Err(error) = kcc::privileges::enforce()"),
            "privileges::enforce() must be main's first statement"
        );
    }
}
