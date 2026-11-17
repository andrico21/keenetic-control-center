//! Which runs of a wizard each user started, so a list reads only its user's records.
//!
//! Each wizard has one index below the runs' directory: `index-wizard.json` for the
//! migrations, `index-preset.json` for the preset runs.
//!
//! The records stay the truth. A run enters the index before its record is first
//! written, so the index may name a run whose record is missing (a write that failed)
//! but never misses a saved run; a list loads each named record and drops the names
//! whose record is gone or names another owner. A missing or unreadable index is built
//! again from the records, by one scan of at most [`SCANNED`] directories.

use alloc::collections::BTreeMap;
use std::{
    fs::{self, DirBuilder, OpenOptions},
    io::{self, Write as _},
    path::{Path, PathBuf},
    sync::{Mutex, MutexGuard, PoisonError},
};

use serde::{Deserialize, Serialize};

use super::{
    flow::Flow,
    ids::is_id,
    store::{StoreError, files::Files},
};

/// Run directories a rebuild reads at most.
const SCANNED: usize = 4096;

/// Held while an index is read and written again, so two requests never lose an entry.
static WRITING: Mutex<()> = Mutex::new(());

/// One wizard's index: each run's owner, by run id.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Index {
    /// The owner of each run, by run id.
    runs: BTreeMap<String, String>,
}

/// The index file of wizard `F` below `root`.
fn path<F>(root: &Path) -> PathBuf
where
    F: Flow,
{
    let stem = F::FILE.trim_suffix(".json");
    root.join(format!("index-{stem}.json"))
}

/// Notes that `owner` started run `id` of wizard `F`, before its record is written.
///
/// # Errors
///
/// Returns read and write failures of the index.
pub(crate) fn enter<F>(store: &Files, id: &str, owner: &str) -> Result<(), StoreError>
where
    F: Flow,
{
    let _writing = writing();
    let mut index = read::<F>(store)?;
    if index.runs.get(id).is_some_and(|known| known == owner) {
        return Ok(());
    }
    drop(index.runs.insert(id.to_owned(), owner.to_owned()));
    write::<F>(store.root(), &index)
}

/// The runs of wizard `F`, each with its owner.
///
/// # Errors
///
/// Returns read and write failures of the index.
pub(crate) fn runs<F>(store: &Files) -> Result<BTreeMap<String, String>, StoreError>
where
    F: Flow,
{
    let _writing = writing();
    Ok(read::<F>(store)?.runs)
}

/// Forgets runs `gone` of wizard `F`: their records are missing or name another owner.
///
/// # Errors
///
/// Returns read and write failures of the index.
pub(crate) fn forget<F>(store: &Files, gone: &[String]) -> Result<(), StoreError>
where
    F: Flow,
{
    if gone.is_empty() {
        return Ok(());
    }
    let _writing = writing();
    let mut index = read::<F>(store)?;
    for id in gone {
        drop(index.runs.remove(id));
    }
    write::<F>(store.root(), &index)
}

/// The index of wizard `F`; a missing or unreadable one is built again from the records
/// and written. The caller holds [`WRITING`].
///
/// # Errors
///
/// Returns read and write failures.
fn read<F>(store: &Files) -> Result<Index, StoreError>
where
    F: Flow,
{
    match fs::read(path::<F>(store.root())) {
        Ok(bytes) => {
            if let Ok(index) = serde_json::from_slice(&bytes) {
                return Ok(index);
            }
            tracing::warn!(
                file = F::FILE,
                "run index unreadable; rebuilt from the runs"
            );
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let index = rebuild::<F>(store)?;
    write::<F>(store.root(), &index)?;
    Ok(index)
}

/// The index of wizard `F` built from its records, reading at most [`SCANNED`]
/// directories.
///
/// # Errors
///
/// Returns directory read failures.
fn rebuild<F>(store: &Files) -> Result<Index, StoreError>
where
    F: Flow,
{
    let entries = match fs::read_dir(store.root()) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Index::default()),
        Err(error) => return Err(error.into()),
    };
    let mut index = Index::default();
    for entry in entries.take(SCANNED) {
        let name = entry?.file_name();
        let Some(id) = name.to_str().filter(|found| is_id(found)) else {
            continue;
        };
        match store.load::<F>(id) {
            Ok(Some(record)) => drop(index.runs.insert(id.to_owned(), record.owner().to_owned())),
            Ok(None) => {}
            Err(error) => {
                tracing::warn!(%error, id, "a run record could not be read for the index");
            }
        }
    }
    Ok(index)
}

/// Writes `index` as the index of wizard `F` below `root`: owner-only, to a temporary
/// name, synced and renamed into place.
///
/// # Errors
///
/// Returns directory, file, sync or rename failures.
fn write<F>(root: &Path, index: &Index) -> Result<(), StoreError>
where
    F: Flow,
{
    let mut bytes = serde_json::to_vec(index).map_err(|_error| StoreError::Malformed)?;
    bytes.push(b'\n');
    let mut builder = DirBuilder::new();
    let _: &mut DirBuilder = builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        let _: &mut DirBuilder = builder.mode(0o700);
    }
    builder.create(root)?;
    let target = path::<F>(root);
    let temporary = target.with_extension("json.tmp");
    let mut options = OpenOptions::new();
    let _: &mut OpenOptions = options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        let _: &mut OpenOptions = options.mode(0o600);
    }
    let mut file = options.open(&temporary)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&temporary, &target)?;
    Ok(())
}

/// [`WRITING`], used as is when a holder panicked: the index is written whole or not.
fn writing() -> MutexGuard<'static, ()> {
    WRITING.lock().unwrap_or_else(PoisonError::into_inner)
}
