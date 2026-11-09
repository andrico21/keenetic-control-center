//! State store and secret tests: atomic writes, schemas, locking, modes, encryption.

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
    extern crate alloc;

    use alloc::collections::BTreeMap;
    use core::error::Error;
    use std::{fs, path::Path};

    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use kcc_app::{
        persist::{Migration, StateDoc, StateError, StateStore},
        secrets::{CryptoError, MasterKey, SealedSecret},
    };
    use secrecy::{ExposeSecret as _, SecretString};
    use serde::{Deserialize, Serialize};
    use serde_json::{Map, Value};
    use tempfile::TempDir;

    /// Test result.
    type TestResult = Result<(), Box<dyn Error>>;

    /// Schema-2 test document; schema 1 called `label` `name`.
    #[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Counter {
        /// A counter.
        count: u32,
        /// A label.
        label: String,
    }

    impl StateDoc for Counter {
        const FILE_NAME: &'static str = "counter.json";
        const SCHEMA: u32 = 2;
        const MIGRATIONS: &'static [Migration] = &[Migration::new(1, rename_name_to_label)];
    }

    /// Schema 1 -> 2: `name` became `label`.
    ///
    /// # Errors
    ///
    /// When `name` is missing.
    fn rename_name_to_label(mut doc: Map<String, Value>) -> Result<Map<String, Value>, String> {
        let name = doc.remove("name").ok_or("schema 1 document without name")?;
        drop(doc.insert("label".to_owned(), name));
        Ok(doc)
    }

    /// Encrypted router credentials, as `routers.json` stores them.
    #[derive(Debug, Default, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Credentials {
        /// Sealed password per router id.
        passwords: BTreeMap<String, SealedSecret>,
    }

    impl StateDoc for Credentials {
        const FILE_NAME: &'static str = "routers.json";
        const SCHEMA: u32 = 1;
        const MIGRATIONS: &'static [Migration] = &[];
    }

    /// Opens a store in a fresh temp dir.
    ///
    /// # Errors
    ///
    /// When the temp dir or store cannot be created.
    fn store() -> Result<(TempDir, StateStore), Box<dyn Error>> {
        let temp = TempDir::new()?;
        let store = StateStore::open(&temp.path().join("state"))?;
        Ok((temp, store))
    }

    /// Writes raw JSON as `counter.json`.
    ///
    /// # Errors
    ///
    /// On I/O failure.
    fn write_raw(store: &StateStore, json: &str) -> TestResult {
        fs::write(store.dir().join(Counter::FILE_NAME), json)?;
        Ok(())
    }

    /// Read-modify-write persists the document with its schema.
    #[test]
    fn update_round_trips_with_schema() -> TestResult {
        let (_temp, store) = store()?;
        assert_eq!(store.read::<Counter>()?, None, "absent before first write");
        let count = store.update(|doc: &mut Counter| {
            doc.count = doc.count.saturating_add(1);
            doc.label = "x".to_owned();
            doc.count
        })?;
        assert_eq!(count, 1, "update returns the closure result");
        let on_disk: Value = serde_json::from_slice(&fs::read(store.dir().join("counter.json"))?)?;
        assert_eq!(
            on_disk.get("schema"),
            Some(&Value::from(2_u32)),
            "schema stored"
        );
        assert_eq!(
            store.read::<Counter>()?,
            Some(Counter {
                count: 1,
                label: "x".to_owned()
            }),
            "read back"
        );
        Ok(())
    }

    /// A temp file left by a crash before the rename is never read and is
    /// removed by the next write.
    #[test]
    fn crash_leftover_temp_is_ignored_then_cleaned() -> TestResult {
        let (_temp, store) = store()?;
        store.write(&Counter {
            count: 7,
            label: "kept".to_owned(),
        })?;
        let leftover = store.dir().join(".counter.json.tmp");
        fs::write(&leftover, b"{\"schema\": 2, \"count\": 99, trunc")?;
        let read = store.read::<Counter>()?.ok_or("file vanished")?;
        assert_eq!(read.count, 7, "the committed file is read, not the temp");
        store.update(|doc: &mut Counter| doc.count = 8)?;
        assert!(
            !leftover.exists(),
            "leftover temp removed by the next write"
        );
        let names: Vec<String> = fs::read_dir(store.dir())?
            .map(|entry| entry.map(|found| found.file_name().to_string_lossy().into_owned()))
            .collect::<Result<_, _>>()?;
        assert!(
            names.iter().all(|name| !name.contains(".tmp")),
            "no temp files remain: {names:?}"
        );
        assert_eq!(
            store.read::<Counter>()?.map(|doc| doc.count),
            Some(8),
            "new value"
        );
        Ok(())
    }

    /// A file from a newer release is refused by read and by update, and
    /// left untouched.
    #[test]
    fn newer_schema_is_refused() -> TestResult {
        let (_temp, store) = store()?;
        let newer = "{\"schema\": 3, \"count\": 1, \"label\": \"\", \"extra\": true}";
        write_raw(&store, newer)?;
        for result in [
            store.read::<Counter>().map(drop),
            store.update(|_: &mut Counter| ()),
        ] {
            assert!(
                matches!(
                    result,
                    Err(StateError::SchemaTooNew {
                        found: 3,
                        supported: 2,
                        file: _
                    })
                ),
                "expected SchemaTooNew, got {result:?}"
            );
        }
        assert_eq!(
            fs::read_to_string(store.dir().join("counter.json"))?,
            newer,
            "file untouched"
        );
        Ok(())
    }

    #[test]
    fn corrupt_state_error_omits_stored_value() -> TestResult {
        let (_temp, store) = store()?;
        let planted = format!("{}{}", "sensitive-", "value".repeat(12));
        write_raw(
            &store,
            &format!(r#"{{"schema":2,"count":"{planted}","label":"x"}}"#),
        )?;

        let Err(error) = store.read::<Counter>() else {
            return Err("invalid count unexpectedly decoded".into());
        };
        let display = error.to_string();
        let debug = format!("{error:?}");

        assert!(!display.contains(&planted), "Display omits stored values");
        assert!(!debug.contains(&planted), "Debug omits stored values");
        assert!(
            display.contains("line ") && display.contains("column "),
            "location remains actionable"
        );
        Ok(())
    }

    /// An older file is migrated, written back at the current schema, and
    /// the directory is copied to `pre-migration-<schema>-<ts>/` first.
    #[test]
    fn older_schema_is_migrated_with_backup() -> TestResult {
        let (_temp, store) = store()?;
        let old = "{\"schema\": 1, \"count\": 4, \"name\": \"legacy\"}";
        write_raw(&store, old)?;
        let read = store.read::<Counter>()?.ok_or("missing")?;
        assert_eq!(read.label, "legacy", "migrated in memory");
        store.update(|doc: &mut Counter| doc.count = 5)?;
        let on_disk: Value = serde_json::from_slice(&fs::read(store.dir().join("counter.json"))?)?;
        assert_eq!(
            on_disk.get("schema"),
            Some(&Value::from(2_u32)),
            "written at schema 2"
        );
        let backups: Vec<_> = fs::read_dir(store.dir())?
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("pre-migration-1-")
            })
            .collect();
        let [backup] = backups.as_slice() else {
            return Err(format!("expected one backup dir, found {}", backups.len()).into());
        };
        assert_eq!(
            fs::read_to_string(backup.path().join("counter.json"))?,
            old,
            "backup holds the original"
        );
        Ok(())
    }

    /// A schema with no registered migration is refused.
    #[test]
    fn missing_migration_is_refused() -> TestResult {
        let (_temp, store) = store()?;
        write_raw(&store, "{\"schema\": 0, \"count\": 1}")?;
        let result = store.read::<Counter>();
        assert!(
            matches!(
                result,
                Err(StateError::MigrationMissing { from: 0, file: _ })
            ),
            "expected MigrationMissing, got {result:?}"
        );
        Ok(())
    }

    /// A second handle cannot take a held lock or lease and gets
    /// `StateLocked` at once; it can after the holder drops it.
    #[test]
    fn second_lock_attempt_fails_with_state_locked() -> TestResult {
        let (_temp, store) = store()?;
        let other = StateStore::open(store.dir())?;
        let held = store.try_lock("counter.json")?;
        let second = other.try_lock("counter.json");
        assert!(
            matches!(second, Err(StateError::StateLocked { path: _ })),
            "expected StateLocked, got {second:?}"
        );
        drop(held);
        drop(other.try_lock("counter.json")?);

        let lease = store.try_lease("home")?;
        let second_lease = other.try_lease("home");
        assert!(
            matches!(second_lease, Err(StateError::StateLocked { path: _ })),
            "expected StateLocked for the lease, got {second_lease:?}"
        );
        assert!(
            lease.path().ends_with("leases/home.lock"),
            "lease path {}",
            lease.path().display()
        );
        drop(lease);
        drop(other.try_lease("home")?);

        let bad = store.try_lease("../escape");
        assert!(
            matches!(bad, Err(StateError::InvalidName { name: _ })),
            "path traversal rejected, got {bad:?}"
        );
        Ok(())
    }

    /// On unix the state dir is 0700 and every file 0600.
    #[cfg(unix)]
    #[test]
    fn created_dir_and_files_are_owner_only() -> TestResult {
        use std::os::unix::fs::PermissionsExt as _;

        /// Permission bits of `path`.
        ///
        /// # Errors
        ///
        /// On I/O failure.
        fn mode(path: &Path) -> Result<u32, Box<dyn Error>> {
            Ok(fs::metadata(path)?.permissions().mode() & 0o777)
        }

        let (_temp, store) = store()?;
        assert_eq!(mode(store.dir())?, 0o700, "state dir");
        store.write(&Counter::default())?;
        assert_eq!(
            mode(&store.dir().join("counter.json"))?,
            0o600,
            "state file"
        );
        assert_eq!(
            mode(&store.dir().join("counter.json.lock"))?,
            0o600,
            "lock file"
        );
        drop(store.try_lease("home")?);
        assert_eq!(mode(&store.dir().join("leases"))?, 0o700, "leases dir");

        let temp = TempDir::new()?;
        let key_path = temp.path().join("config/master.key");
        drop(MasterKey::load_or_create(&key_path)?);
        assert_eq!(mode(&key_path)?, 0o600, "master key");
        assert_eq!(
            mode(key_path.parent().ok_or("no parent")?)?,
            0o700,
            "key dir"
        );

        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o644))?;
        let loose = MasterKey::load(&key_path);
        assert!(
            matches!(loose, Err(CryptoError::KeyPermissions { path: _ })),
            "group-readable key refused, got {loose:?}"
        );
        Ok(())
    }

    /// Sealed credentials survive a state round trip and only open with the
    /// right key and owner; the plaintext never reaches the file.
    #[test]
    fn encrypted_round_trip_and_wrong_key() -> TestResult {
        let (_temp, store) = store()?;
        let key = MasterKey::generate()?;
        let password = SecretString::from("correct horse battery staple");
        let sealed = key.seal("home", &password)?;
        store.update(|doc: &mut Credentials| {
            drop(doc.passwords.insert("home".to_owned(), sealed));
        })?;

        let raw = fs::read_to_string(store.dir().join("routers.json"))?;
        assert!(!raw.contains("battery"), "plaintext is not stored");

        let doc = store.read::<Credentials>()?.ok_or("missing")?;
        let stored = doc.passwords.get("home").ok_or("no entry")?;
        assert_eq!(
            key.open("home", stored)?.expose_secret(),
            password.expose_secret(),
            "round trip"
        );

        let wrong_key = MasterKey::generate()?.open("home", stored);
        assert!(
            matches!(wrong_key, Err(CryptoError::Decrypt)),
            "wrong key gives a clean error, got {wrong_key:?}"
        );
        let wrong_owner = key.open("office", stored);
        assert!(
            matches!(wrong_owner, Err(CryptoError::Decrypt)),
            "ciphertext bound to its router id, got {wrong_owner:?}"
        );
        let mut tampered = stored.clone();
        let mut bytes = STANDARD.decode(&tampered.ciphertext)?;
        let first = bytes.first_mut().ok_or("empty ciphertext")?;
        *first ^= 1;
        tampered.ciphertext = STANDARD.encode(&bytes);
        let tampered_result = key.open("home", &tampered);
        assert!(
            matches!(tampered_result, Err(CryptoError::Decrypt)),
            "tampering detected, got {tampered_result:?}"
        );
        let mut garbled = stored.clone();
        garbled.nonce = "not base64!".to_owned();
        let garbled_result = key.open("home", &garbled);
        assert!(
            matches!(garbled_result, Err(CryptoError::Malformed { reason: _ })),
            "malformed nonce is an error, got {garbled_result:?}"
        );
        Ok(())
    }

    /// The master key is created once and reloaded; a bad length is refused.
    #[test]
    fn master_key_file_is_created_once_and_reloaded() -> TestResult {
        let temp = TempDir::new()?;
        let path = temp.path().join("config/master.key");
        let created = MasterKey::load_or_create(&path)?;
        assert_eq!(fs::read(&path)?.len(), 32, "32 raw bytes");
        let reloaded = MasterKey::load_or_create(&path)?;
        let sealed = created.seal("home", &SecretString::from("pw"))?;
        assert_eq!(
            reloaded.open("home", &sealed)?.expose_secret(),
            "pw",
            "same key"
        );
        assert!(
            !format!("{created:?}").contains(&format!("{:?}", fs::read(&path)?)),
            "Debug redacts the key"
        );

        let short = temp.path().join("short.key");
        fs::write(&short, [0_u8; 16])?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&short, fs::Permissions::from_mode(0o600))?;
        }
        let result = MasterKey::load(&short);
        assert!(
            matches!(result, Err(CryptoError::KeyLength { path: _ })),
            "short key refused, got {result:?}"
        );
        Ok(())
    }
}
