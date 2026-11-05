//! `catalog fetch`: download the CLI manual of every model for one firmware version.

use core::time::Duration;
use std::{
    fs, io,
    path::{Path, PathBuf},
};

use jiff::{Timestamp, tz::TimeZone};
use sha2::{Digest as _, Sha256};
use ureq::Agent;

use crate::{
    Verdict,
    catalog::{self, Entry, Lock},
    failure::GateError,
};

/// Per-request timeout; the manuals are several megabytes.
const TIMEOUT: Duration = Duration::from_secs(300);

/// Largest PDF accepted, in bytes.
const MAX_PDF_BYTES: u64 = 256 * 1024 * 1024;

/// UTC date of today as `YYYY-MM-DD`.
pub(crate) fn today() -> String {
    Timestamp::now().to_zoned(TimeZone::UTC).date().to_string()
}

/// Lowercase hex SHA-256 of `bytes`.
fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .flat_map(|byte| [byte >> 4_u8, byte & 0x0f_u8])
        .filter_map(|nibble| char::from_digit(u32::from(nibble), 16))
        .collect()
}

/// Fetches every model of `models` (or of `catalog/sources.toml`) for `version`.
///
/// A 404 records the model as absent. Any other status or a transport error aborts.
///
/// # Errors
///
/// Returns a [`GateError`] on a transport error, an unexpected status or an I/O error.
pub(crate) fn run<W>(
    root: &Path,
    version: &str,
    models_file: Option<&Path>,
    out: &mut W,
) -> Result<Verdict, GateError>
where
    W: io::Write,
{
    let list = models_file.map_or_else(|| catalog::sources_path(root), Path::to_path_buf);
    let models = catalog::read_models(&list)?;
    let dir: PathBuf = catalog::cache_dir(root).join(version);
    let lock_path = catalog::lock_path(root);
    let mut lock = Lock::load(&lock_path)?;
    let agent: Agent = Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(TIMEOUT))
        .build()
        .into();
    let date = today();
    let (mut found, mut absent) = (0_usize, 0_usize);
    for model in &models {
        let entry = fetch_one(&agent, &dir, version, model, &date)?;
        writeln!(
            out,
            "fetch {version} {model}: {} {}",
            entry.status,
            entry
                .sha256
                .as_deref()
                .map_or_else(|| "absent".to_owned(), ToOwned::to_owned)
        )?;
        if entry.absent {
            absent = absent.saturating_add(1);
        } else {
            found = found.saturating_add(1);
        }
        lock.upsert(entry);
    }
    fs::create_dir_all(lock_path.parent().ok_or(GateError::NoRoot)?).map_err(|source| {
        GateError::Write {
            path: lock_path.clone(),
            detail: source.to_string(),
        }
    })?;
    lock.save(&lock_path)?;
    writeln!(
        out,
        "fetch {version}: {found} fetched, {absent} absent, lock written to {}",
        lock_path.display()
    )?;
    Ok(Verdict::Pass)
}

/// Requests one manual and stores it under `dir` on a 200.
///
/// # Errors
///
/// Returns a [`GateError`] on a transport error, an unexpected status or an I/O error.
fn fetch_one(
    agent: &Agent,
    dir: &Path,
    version: &str,
    model: &str,
    date: &str,
) -> Result<Entry, GateError> {
    let url = catalog::manual_url(version, model);
    let http_error = |detail: String| GateError::Http {
        url: url.clone(),
        detail,
    };
    let response = agent
        .get(&url)
        .call()
        .map_err(|source| http_error(source.to_string()))?;
    let status = response.status().as_u16();
    let mut entry = Entry {
        version: version.to_owned(),
        model: model.to_owned(),
        url: url.clone(),
        status,
        absent: true,
        sha256: None,
        size: None,
        fetch_date: date.to_owned(),
    };
    match status {
        404 => Ok(entry),
        200 => {
            let bytes = response
                .into_body()
                .with_config()
                .limit(MAX_PDF_BYTES)
                .read_to_vec()
                .map_err(|source| http_error(source.to_string()))?;
            let path = dir.join(format!("{}.pdf", model.to_lowercase()));
            let write_error = |source: io::Error| GateError::Write {
                path: path.clone(),
                detail: source.to_string(),
            };
            fs::create_dir_all(dir).map_err(write_error)?;
            fs::write(&path, &bytes).map_err(write_error)?;
            entry.absent = false;
            entry.sha256 = Some(sha256_hex(&bytes));
            entry.size = u64::try_from(bytes.len()).ok();
            Ok(entry)
        }
        other => Err(http_error(format!("unexpected HTTP status {other}"))),
    }
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use super::{sha256_hex, today};

    #[test]
    fn sha256_of_empty_input_is_the_known_digest() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "empty digest"
        );
    }

    #[test]
    fn today_is_an_iso_date() {
        let date = today();
        assert_eq!(date.len(), 10, "YYYY-MM-DD: {date}");
    }
}
