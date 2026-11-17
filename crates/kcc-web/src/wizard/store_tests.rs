//! The migrations directory's files: records round trip, sealed parts stay bound to
//! their migration.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#![expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
use alloc::sync::Arc;
use core::error::Error;
use std::{
    fs,
    io::{self, Write},
    sync::{Mutex, PoisonError},
};

use kcc_app::secrets::MasterKey;
use secrecy::{ExposeSecret as _, SecretString};
use tempfile::TempDir;
use tracing::subscriber;

use super::{Sealed, Store};
use crate::{migrate_wizard::record::Record, wizard::flow::Flow as _};

#[tokio::test]
async fn records_round_trip_and_sealed_parts_stay_bound_to_their_migration()
-> Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let store = Store::new(directory.path());
    let key = MasterKey::from_bytes([9_u8; 32]);
    let id = "1700000000-0001020304050607";
    let record = Record::new(id.to_owned(), "admin".to_owned(), 5);
    store.save(&record).await?;
    let loaded = store.load::<Record>(id).await?.ok_or("record")?;
    assert_eq!(loaded.owner(), "admin", "round trip");
    assert!(
        store.load::<Record>("../escape").await?.is_none(),
        "ids are checked"
    );
    let secret = SecretString::from("interface Bridge0\n".to_owned());
    store.seal(&key, id, Sealed::Source, &secret).await?;
    let written = fs::read_to_string(
        directory
            .path()
            .join("migrations")
            .join(id)
            .join("source.sealed"),
    )?;
    assert!(!written.contains("Bridge0"), "sealed on disk");
    let opened = store
        .open(&key, id, Sealed::Source)
        .await?
        .ok_or("sealed")?;
    assert_eq!(opened.expose_secret(), secret.expose_secret(), "opens");
    let other = "1700000000-0001020304050608";
    fs::create_dir_all(directory.path().join("migrations").join(other))?;
    let copied = fs::copy(
        directory
            .path()
            .join("migrations")
            .join(id)
            .join("source.sealed"),
        directory
            .path()
            .join("migrations")
            .join(other)
            .join("source.sealed"),
    )?;
    assert!(copied > 0, "the sealed part was copied");
    assert!(
        store.open(&key, other, Sealed::Source).await.is_err(),
        "a copied part does not open under another migration"
    );
    assert_eq!(
        store.list::<Record>("admin").await?.len(),
        1,
        "listed by owner"
    );
    assert!(
        store.list::<Record>("someone").await?.is_empty(),
        "never another owner's"
    );
    Ok(())
}

/// The formatted events written to it.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Write for Captured {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// W2-11: a run record that cannot be read while the index is built again is logged as a
/// warning naming the run, not dropped silently.
#[tokio::test]
async fn an_unreadable_run_is_logged_when_the_index_is_built_again() -> Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let id = "1700000000-0001020304050607";
    let run = directory.path().join("migrations").join(id);
    fs::create_dir_all(&run)?;
    fs::write(run.join(Record::FILE), b"{ not a record")?;
    let captured = Captured::default();
    let sink = captured.clone();
    let collector = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(move || sink.clone())
        .finish();
    let _installed = subscriber::set_default(collector);

    let listed = Store::new(directory.path()).list::<Record>("admin").await?;

    assert!(listed.is_empty(), "the unreadable run is not listed");
    let logged = String::from_utf8(
        captured
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone(),
    )?;
    assert!(
        logged
            .lines()
            .any(|line| line.contains("WARN") && line.contains(id)),
        "a warning names the run: {logged:?}"
    );
    Ok(())
}
