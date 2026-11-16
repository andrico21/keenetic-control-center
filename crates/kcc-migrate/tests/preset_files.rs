//! Preset records on disk: owner-only atomic writes and listing past a torn record.

#[cfg(test)]
mod tests {
    #![expect(
        clippy::missing_errors_doc,
        clippy::missing_panics_doc,
        clippy::panic_in_result_fn,
        reason = "integration-test assertions define the preset file contract"
    )]

    extern crate alloc;

    use alloc::sync::Arc;
    use core::error::Error;
    use std::{
        fs,
        io::{self, Write},
        sync::Mutex,
    };

    use kcc_app::{
        permissions::{Permission, Role},
        persist::StateStore,
        secrets::MasterKey,
    };
    use kcc_config::config_text::parse;
    use kcc_migrate::presets::{
        model::{CaptureRequest, PresetSource, PresetSourceKind},
        store::PresetStore,
    };
    use tempfile::TempDir;
    use tracing::{Level, subscriber::set_default};

    /// Collects formatted tracing output.
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

    /// SEC2-13: a saved preset record goes through the state store's private
    /// writer: the directory is 0700, the record 0600, and no temporary file stays.
    #[cfg(unix)]
    #[test]
    fn saved_preset_record_is_owner_only() -> Result<(), Box<dyn Error>> {
        use std::os::unix::fs::PermissionsExt as _;

        let temporary = TempDir::new()?;
        drop(saved(&temporary, "private")?);

        let directory = temporary.path().join("presets");
        let mode = |name: &str| {
            fs::metadata(directory.join(name)).map(|found| found.permissions().mode() & 0o777)
        };
        assert_eq!(mode("")?, 0o700, "preset directory");
        assert_eq!(mode("private.json")?, 0o600, "preset record");
        let names = fs::read_dir(&directory)?
            .map(|entry| entry.map(|item| item.file_name().to_string_lossy().into_owned()))
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(names, ["private.json"]);
        Ok(())
    }

    /// SEC2-13 (critic correction): a torn record does not make `list` fail;
    /// it is skipped and its file name is logged.
    #[test]
    fn torn_record_is_skipped_and_logged() -> Result<(), Box<dyn Error>> {
        let temporary = TempDir::new()?;
        let (store, administrator) = saved(&temporary, "intact")?;
        fs::write(
            temporary.path().join("presets/torn.json"),
            "{\"schema\": 1, \"sou",
        )?;
        let capture = Capture(Arc::new(Mutex::new(Vec::new())));
        let sink = capture.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(Level::WARN)
            .with_ansi(false)
            .with_writer(move || sink.clone())
            .finish();
        let guard = set_default(subscriber);

        let listed = store.list(&administrator)?;

        drop(guard);
        let ids = listed
            .iter()
            .map(|preset| preset.id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(ids, ["intact"]);
        let logged = String::from_utf8(
            capture
                .0
                .lock()
                .map_err(|_error| "capture poisoned")?
                .clone(),
        )?;
        assert!(logged.contains("torn.json"), "{logged}");
        Ok(())
    }

    /// A store in `temporary` holding one captured preset `id`, and its administrator.
    fn saved(temporary: &TempDir, id: &str) -> Result<(PresetStore, Role), Box<dyn Error>> {
        let store = PresetStore::new(
            StateStore::open(temporary.path())?,
            MasterKey::from_bytes([17_u8; 32]),
        );
        let administrator = Role::new(
            "admin".to_owned(),
            [Permission::Read, Permission::Migrate],
            vec!["*".to_owned()],
        );
        let request = CaptureRequest::new(
            id.to_owned(),
            "Preset".to_owned(),
            String::new(),
            vec!["dns-records-routing".to_owned()],
            PresetSource::new(
                PresetSourceKind::Router,
                Some("lab-one".to_owned()),
                "KN-1811".to_owned(),
                "5.1.1".to_owned(),
                1_800_000_000,
            ),
            "tester".to_owned(),
        );
        drop(store.capture(
            &administrator,
            &parse("ip host example.test 192.0.2.1\n")?,
            request,
        )?);
        Ok((store, administrator))
    }
}
