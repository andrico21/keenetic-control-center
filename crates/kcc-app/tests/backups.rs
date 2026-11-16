//! Backup collision and retention behavior.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "test assertions deliberately panic and test helpers are not public API"
)]
mod tests {
    extern crate alloc;

    use alloc::sync::Arc;
    use core::{
        error::Error,
        sync::atomic::{AtomicU64, Ordering},
        time::Duration,
    };
    use std::{
        fs,
        io::{self, Write},
        sync::{Barrier, Mutex},
    };

    use kcc_app::{
        accounts::Clock,
        backups::{BackupRetention, BackupStore},
        persist::StateStore,
        secrets::MasterKey,
    };
    use secrecy::{ExposeSecret as _, SecretString};
    use tempfile::TempDir;
    use tokio::task::spawn_blocking;
    use tracing::{Level, subscriber::set_default};

    type TestResult = Result<(), Box<dyn Error>>;

    #[derive(Debug)]
    struct FixedClock(AtomicU64);

    impl FixedClock {
        const fn new(now: u64) -> Self {
            Self(AtomicU64::new(now))
        }

        fn set(&self, now: u64) {
            self.0.store(now, Ordering::SeqCst);
        }
    }

    impl Clock for FixedClock {
        fn unix_seconds(&self) -> u64 {
            self.0.load(Ordering::SeqCst)
        }
    }

    #[derive(Clone)]
    struct Capture(Arc<Mutex<Vec<u8>>>);

    impl Write for Capture {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0
                .lock()
                .map_err(|_error| io::Error::other("capture poisoned"))?
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn store(clock: Arc<FixedClock>) -> Result<(TempDir, BackupStore), Box<dyn Error>> {
        let directory = TempDir::new()?;
        let state = StateStore::open(&directory.path().join("state"))?;
        let source: Arc<dyn Clock> = clock;
        let backups = BackupStore::new(state, MasterKey::from_bytes([7_u8; 32])).with_clock(source);
        Ok((directory, backups))
    }

    #[test]
    fn same_second_creates_keep_both_and_preserve_first_content() -> TestResult {
        let (_directory, backups) = store(Arc::new(FixedClock::new(100)))?;
        let first = backups.create("router", "manual", &SecretString::from("first".to_owned()))?;

        let second =
            backups.create("router", "manual", &SecretString::from("second".to_owned()))?;

        assert_ne!(first.name, second.name);
        assert_eq!(backups.list("router")?.len(), 2);
        assert_eq!(backups.get("router", &first.name)?.expose_secret(), "first");
        assert_eq!(
            backups.get("router", &second.name)?.expose_secret(),
            "second"
        );
        Ok(())
    }

    #[tokio::test]
    async fn concurrent_same_second_creates_lose_none() -> TestResult {
        const TASKS: usize = 8;
        let (_directory, backups) = store(Arc::new(FixedClock::new(200)))?;
        let shared = Arc::new(backups);
        let barrier = Arc::new(Barrier::new(TASKS));
        let mut joins = Vec::new();
        for number in 0..TASKS {
            let store = Arc::clone(&shared);
            let ready = Arc::clone(&barrier);
            joins.push(spawn_blocking(move || {
                let _wait = ready.wait();
                store.create(
                    "router",
                    "manual",
                    &SecretString::from(format!("content-{number}")),
                )
            }));
        }
        for join in joins {
            drop(join.await??);
        }

        let listed = shared.list("router")?;

        assert_eq!(listed.len(), TASKS);
        for number in 0..TASKS {
            let expected = format!("content-{number}");
            assert!(listed.iter().any(|backup| {
                shared
                    .get("router", &backup.name)
                    .is_ok_and(|text| text.expose_secret() == expected)
            }));
        }
        Ok(())
    }

    #[test]
    fn automatic_count_retention_keeps_newest_three() -> TestResult {
        let clock = Arc::new(FixedClock::new(300));
        let (directory, backups) = store(Arc::clone(&clock))?;
        let state = StateStore::open(&directory.path().join("state"))?;
        let source: Arc<dyn Clock> = Arc::<FixedClock>::clone(&clock);
        let retained = BackupStore::new(state, MasterKey::from_bytes([8_u8; 32]))
            .with_clock(source)
            .with_retention(BackupRetention::new(Duration::ZERO, 3));
        for second in 300..306 {
            clock.set(second);
            drop(retained.create(
                "router",
                "automatic",
                &SecretString::from(format!("content-{second}")),
            )?);
        }

        let listed = retained.list("router")?;

        assert_eq!(
            listed
                .iter()
                .map(|backup| backup.created_at)
                .collect::<Vec<_>>(),
            [305, 304, 303]
        );
        drop(backups);
        Ok(())
    }

    #[test]
    fn automatic_age_retention_prunes_old_backup_but_keeps_new_create() -> TestResult {
        let clock = Arc::new(FixedClock::new(400));
        let (_directory, backups) = store(Arc::clone(&clock))?;
        let retained = backups.with_retention(BackupRetention::new(Duration::from_secs(10), 0));
        drop(retained.create("router", "old", &SecretString::from("old".to_owned()))?);
        clock.set(411);

        let newest = retained.create("router", "new", &SecretString::from("new".to_owned()))?;

        assert_eq!(retained.list("router")?, vec![newest]);
        Ok(())
    }

    #[test]
    fn zero_retention_limits_prune_nothing() -> TestResult {
        let clock = Arc::new(FixedClock::new(500));
        let (_directory, backups) = store(Arc::clone(&clock))?;
        let retained = backups.with_retention(BackupRetention::new(Duration::ZERO, 0));
        for second in 500..506 {
            clock.set(second);
            drop(retained.create(
                "router",
                "manual",
                &SecretString::from(format!("content-{second}")),
            )?);
        }

        assert_eq!(retained.list("router")?.len(), 6);
        Ok(())
    }

    /// B-21: a malformed file beside valid backups must not stop listing or retention.
    #[test]
    fn malformed_backup_file_does_not_stop_retention() -> TestResult {
        let capture = Capture(Arc::new(Mutex::new(Vec::new())));
        let sink = capture.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(Level::WARN)
            .with_ansi(false)
            .with_writer(move || sink.clone())
            .finish();
        let _subscriber = set_default(subscriber);
        let clock = Arc::new(FixedClock::new(600));
        let (directory, backups) = store(Arc::clone(&clock))?;
        let retained = backups.with_retention(BackupRetention::new(Duration::ZERO, 2));
        let router_dir = directory.path().join("state/backups/router");
        fs::create_dir_all(&router_dir)?;
        fs::write(router_dir.join("1-broken.txt"), b"not json")?;
        for second in 600..604 {
            clock.set(second);
            drop(retained.create(
                "router",
                "manual",
                &SecretString::from(format!("content-{second}")),
            )?);
        }

        let listed = retained.listing("router")?;

        assert_eq!(
            listed.backups.len(),
            2,
            "retention keeps the newest two readable"
        );
        assert_eq!(listed.unreadable, 1);
        assert_eq!(fs::read(router_dir.join("1-broken.txt"))?, b"not json");
        let output = String::from_utf8(
            capture
                .0
                .lock()
                .map_err(|_error| "capture poisoned")?
                .clone(),
        )?;
        assert!(!output.contains("retention failed"), "{output}");
        assert!(output.contains("1-broken.txt"), "{output}");
        Ok(())
    }
}
