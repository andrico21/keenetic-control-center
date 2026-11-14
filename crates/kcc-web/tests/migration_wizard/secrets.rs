//! What the tests look for on disk: every file below a directory, and the secrets that
//! must not be among them.
#![expect(
    clippy::missing_errors_doc,
    reason = "test support is not rendered API documentation; every error fails the test"
)]

use std::{fs, path::Path};

use crate::support::{outcome::TestResult, web::Fixture};

/// Every file below `dir`, by path, as text.
pub(crate) fn files(dir: &Path) -> TestResult<Vec<(String, String)>> {
    let mut found = Vec::new();
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            found.extend(files(&path)?);
        } else {
            let bytes = fs::read(&path)?;
            found.push((
                path.display().to_string(),
                String::from_utf8_lossy(&bytes).into_owned(),
            ));
        }
    }
    Ok(found)
}

/// Fails, naming the file but not the secret, when a file below `dir` holds one of
/// `secrets`.
pub(crate) fn absent(dir: &Path, secrets: &[&str]) -> TestResult {
    for (path, content) in files(dir)? {
        if secrets.iter().any(|secret| content.contains(secret)) {
            return Err(format!("{path} holds a secret").into());
        }
    }
    Ok(())
}

/// The source router's stored password hash of `alice`.
pub(crate) fn source_hash(fixture: &Fixture) -> TestResult<String> {
    Ok(fixture
        .router("giga")?
        .startup_config_text()
        .split("password md5 ")
        .nth(1)
        .and_then(|tail| tail.split_whitespace().next())
        .ok_or("the source stores a hash")?
        .to_owned())
}
