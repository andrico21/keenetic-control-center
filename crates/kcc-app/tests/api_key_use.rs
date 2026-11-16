//! API-key "last used" recording: at most one state write per key per minute.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "test assertions deliberately panic and are not rendered API documentation"
)]
mod tests {
    extern crate alloc;

    use alloc::sync::Arc;
    use core::{
        error::Error,
        sync::atomic::{AtomicU64, Ordering},
    };

    use kcc_app::{
        accounts::Clock,
        api_key_use::{KEY_USE_INTERVAL, KeyUseRecorder},
        api_keys::{ApiKeysDocument, create_api_key},
        permissions::{Permission, Role},
        persist::StateStore,
    };
    use tempfile::TempDir;

    type TestResult = Result<(), Box<dyn Error>>;

    /// A clock the test moves by hand.
    #[derive(Debug, Default)]
    struct HandClock(AtomicU64);

    impl Clock for HandClock {
        fn unix_seconds(&self) -> u64 {
            self.0.load(Ordering::SeqCst)
        }
    }

    /// The stored last use of `name`.
    fn last_used(store: &StateStore, name: &str) -> Result<Option<u64>, Box<dyn Error>> {
        Ok(store
            .read::<ApiKeysDocument>()?
            .unwrap_or_default()
            .keys
            .into_iter()
            .find(|key| key.name == name)
            .and_then(|key| key.last_used_at))
    }

    #[test]
    fn a_key_use_is_written_at_most_once_a_minute() -> TestResult {
        let directory = TempDir::new()?;
        let store = StateStore::open(directory.path())?;
        drop(create_api_key(
            &store,
            &Role::new("admin".to_owned(), Permission::ALL, vec!["*".to_owned()]),
            "agent".to_owned(),
            "viewer".to_owned(),
            1,
        )?);
        drop(create_api_key(
            &store,
            &Role::new("admin".to_owned(), Permission::ALL, vec!["*".to_owned()]),
            "other".to_owned(),
            "viewer".to_owned(),
            1,
        )?);
        let clock = Arc::new(HandClock(AtomicU64::new(1_000)));
        let recorder = KeyUseRecorder::new(store.clone(), Arc::<HandClock>::clone(&clock));

        let first = recorder.note("agent").ok_or("the first use is due")?;
        assert!(first.persist()?, "recorded");
        assert_eq!(last_used(&store, "agent")?, Some(1_000), "first use");

        clock
            .0
            .store(1_000 + KEY_USE_INTERVAL - 1, Ordering::SeqCst);
        assert!(recorder.note("agent").is_none(), "within the minute");
        assert_eq!(last_used(&store, "agent")?, Some(1_000), "state untouched");
        assert!(recorder.note("other").is_some(), "the throttle is per key");

        clock.0.store(1_000 + KEY_USE_INTERVAL, Ordering::SeqCst);
        let later = recorder.note("agent").ok_or("a minute later")?;
        assert!(later.persist()?, "recorded again");
        assert_eq!(
            last_used(&store, "agent")?,
            Some(1_000 + KEY_USE_INTERVAL),
            "the minute-old use"
        );
        Ok(())
    }

    #[test]
    fn a_revoked_key_is_not_recreated() -> TestResult {
        let directory = TempDir::new()?;
        let store = StateStore::open(directory.path())?;
        let recorder = KeyUseRecorder::new(store.clone(), Arc::new(HandClock::default()));
        let gone = recorder.note("revoked").ok_or("due")?;
        assert!(!gone.persist()?, "nothing to update");
        assert!(
            store
                .read::<ApiKeysDocument>()?
                .unwrap_or_default()
                .keys
                .is_empty(),
            "no record appears"
        );
        Ok(())
    }
}
