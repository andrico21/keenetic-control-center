//! Source-level startup security invariants.

#[cfg(test)]
#[expect(
    clippy::expect_used,
    clippy::missing_panics_doc,
    reason = "source guards fail through test assertions"
)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
    };

    fn rust_sources(root: &Path, files: &mut Vec<PathBuf>) {
        for entry in fs::read_dir(root).expect("source directory is readable") {
            let path = entry.expect("directory entry is readable").path();
            match (
                path.is_dir(),
                path.extension().is_some_and(|extension| extension == "rs"),
            ) {
                (true, _) => rust_sources(&path, files),
                (false, true) => files.push(path),
                (false, false) => {}
            }
        }
    }

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

    #[test]
    fn workspace_crates_never_execute_subprocesses() {
        let crates = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("kcc has a crates parent");
        let mut files = Vec::new();
        for entry in fs::read_dir(crates).expect("crates directory is readable") {
            let source_root = entry.expect("crate entry is readable").path().join("src");
            if source_root.is_dir() {
                rust_sources(&source_root, &mut files);
            }
        }
        for file in files {
            let source = fs::read_to_string(&file).expect("Rust source is readable");
            for spawner in ["std::process::Command", "Command::new", "exec("] {
                assert!(
                    !source.contains(spawner),
                    "`{spawner}` in {} would make the inherited bounding set actionable",
                    file.display()
                );
            }
        }
    }
}
