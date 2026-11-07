//! The migrations directory's files: records round trip, sealed parts stay bound to
//! their migration.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#![expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
use core::error::Error;
use std::fs;

use kcc_app::secrets::MasterKey;
use secrecy::{ExposeSecret as _, SecretString};
use tempfile::TempDir;

use super::{Sealed, Store};
use crate::migrate_wizard::record::Record;

#[test]
fn records_round_trip_and_sealed_parts_stay_bound_to_their_migration() -> Result<(), Box<dyn Error>>
{
    let directory = TempDir::new()?;
    let store = Store::new(directory.path());
    let key = MasterKey::from_bytes([9_u8; 32]);
    let id = "1700000000-0001020304050607";
    let record = Record::new(id.to_owned(), "admin".to_owned(), 5);
    store.save(&record)?;
    let loaded = store.load(id)?.ok_or("record")?;
    assert_eq!(loaded.owner(), "admin", "round trip");
    assert!(store.load("../escape")?.is_none(), "ids are checked");
    let secret = SecretString::from("interface Bridge0\n".to_owned());
    store.seal(&key, id, Sealed::Source, &secret)?;
    let written = fs::read_to_string(
        directory
            .path()
            .join("migrations")
            .join(id)
            .join("source.sealed"),
    )?;
    assert!(!written.contains("Bridge0"), "sealed on disk");
    let opened = store.open(&key, id, Sealed::Source)?.ok_or("sealed")?;
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
        store.open(&key, other, Sealed::Source).is_err(),
        "a copied part does not open under another migration"
    );
    assert_eq!(store.list("admin")?.len(), 1, "listed by owner");
    assert!(store.list("someone")?.is_empty(), "never another owner's");
    Ok(())
}
