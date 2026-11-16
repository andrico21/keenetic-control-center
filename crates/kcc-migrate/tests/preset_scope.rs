//! Preset router scope in the store: a capture replaces a stored preset only within the
//! caller's scope, and a preset of another scope answers like a missing one.

#[cfg(test)]
mod tests {
    #![expect(
        clippy::missing_errors_doc,
        clippy::missing_panics_doc,
        clippy::panic_in_result_fn,
        reason = "integration-test assertions define the preset scope contract"
    )]

    use core::error::Error;
    use std::fs;

    use kcc_app::{
        permissions::{Permission, Role},
        persist::StateStore,
        secrets::MasterKey,
    };
    use kcc_config::config_text::parse;
    use kcc_migrate::presets::{
        model::{CaptureRequest, PresetSource, PresetSourceKind},
        store::{PresetError, PresetStore},
    };
    use tempfile::TempDir;

    /// The configuration every capture reads.
    const SOURCE: &str =
        "ip host example.test 192.0.2.1\nip route 198.51.100.0 255.255.255.0 203.0.113.1\n";

    /// A store with the preset `office` captured from router `office` by `admin`.
    struct Fixture {
        /// Keeps the state directory alive.
        directory: TempDir,
        /// The store under test.
        store: PresetStore,
    }

    impl Fixture {
        fn new() -> Result<Self, Box<dyn Error>> {
            let directory = TempDir::new()?;
            let store = PresetStore::new(
                StateStore::open(directory.path())?,
                MasterKey::from_bytes([23_u8; 32]),
            );
            drop(store.capture(
                &admin(),
                &parse(SOURCE)?,
                request("office", "office", "dns-records-routing"),
            )?);
            Ok(Self { directory, store })
        }

        fn record(&self, id: &str) -> Result<Vec<u8>, Box<dyn Error>> {
            Ok(fs::read(
                self.directory.path().join(format!("presets/{id}.json")),
            )?)
        }
    }

    fn admin() -> Role {
        Role::new(
            "admin".to_owned(),
            [Permission::Read, Permission::Migrate],
            vec!["*".to_owned()],
        )
    }

    fn lab() -> Role {
        Role::new(
            "lab".to_owned(),
            [Permission::Read, Permission::Migrate],
            vec!["lab".to_owned()],
        )
    }

    fn request(id: &str, router: &str, group: &str) -> CaptureRequest {
        CaptureRequest::new(
            id.to_owned(),
            id.to_owned(),
            String::new(),
            vec![group.to_owned()],
            PresetSource::new(
                PresetSourceKind::Router,
                Some(router.to_owned()),
                "KN-1811".to_owned(),
                "5.1.1".to_owned(),
                1_800_000_000,
            ),
            "tester".to_owned(),
        )
    }

    /// E-02, G-02: a capture scoped to `lab` that names the id of a preset sourced from
    /// `office` is refused, and the stored record stays byte for byte.
    #[test]
    fn a_scoped_capture_cannot_replace_a_preset_of_another_scope() -> Result<(), Box<dyn Error>> {
        let fixture = Fixture::new()?;
        let before = fixture.record("office")?;

        let replaced = fixture.store.capture(
            &lab(),
            &parse(SOURCE)?,
            request("office", "lab", "static-routes"),
        );

        assert!(
            matches!(replaced, Err(PresetError::Forbidden)),
            "{replaced:?}"
        );
        assert_eq!(fixture.record("office")?, before);
        let kept = fixture.store.get(&admin(), "office")?;
        assert_eq!(kept.source_router(), Some("office"));
        assert_eq!(kept.groups, ["dns-records-routing"]);
        Ok(())
    }

    /// E-02, G-02: replacing stays possible within the caller's scope, so a preset is
    /// recaptured under its id by whoever holds `Migrate` on its source router.
    #[test]
    fn a_caller_recaptures_a_preset_of_its_own_scope() -> Result<(), Box<dyn Error>> {
        let fixture = Fixture::new()?;
        let source = parse(SOURCE)?;
        drop(fixture.store.capture(
            &lab(),
            &source,
            request("bench", "lab", "dns-records-routing"),
        )?);

        drop(
            fixture
                .store
                .capture(&lab(), &source, request("bench", "lab", "static-routes"))?,
        );
        drop(fixture.store.capture(
            &admin(),
            &source,
            request("office", "office", "static-routes"),
        )?);

        assert_eq!(
            fixture.store.get(&lab(), "bench")?.groups,
            ["static-routes"]
        );
        assert_eq!(
            fixture.store.get(&admin(), "office")?.groups,
            ["static-routes"]
        );
        Ok(())
    }

    /// E-02, G-02: `get`, `delete` and both apply reads answer a preset of another scope
    /// exactly like a missing id, `list` hides it, and nothing is removed.
    #[test]
    fn a_preset_of_another_scope_answers_like_a_missing_one() -> Result<(), Box<dyn Error>> {
        let fixture = Fixture::new()?;
        let before = fixture.record("office")?;
        let store = &fixture.store;
        let role = lab();

        for id in ["office", "absent"] {
            let answers = [
                store.get(&role, id).map(drop),
                store.delete(&role, id),
                store.get_for_apply(&role, id).map(drop),
                store.load_for_apply(&role, id).map(drop),
            ];
            for answer in answers {
                assert!(
                    matches!(answer, Err(PresetError::NotFound)),
                    "{id}: {answer:?}"
                );
            }
        }
        assert!(store.list(&role)?.is_empty());
        assert_eq!(fixture.record("office")?, before);
        Ok(())
    }

    /// E-02, G-02: a record whose source cannot be read is replaced only by a caller whose
    /// scope covers every router, and a scoped caller sees it as missing.
    #[test]
    fn an_unreadable_record_is_replaced_only_by_an_unscoped_caller() -> Result<(), Box<dyn Error>> {
        let fixture = Fixture::new()?;
        let path = fixture.directory.path().join("presets/damaged.json");
        fs::write(&path, b"{\"schema\":1}")?;
        let source = parse(SOURCE)?;

        let refused =
            fixture
                .store
                .capture(&lab(), &source, request("damaged", "lab", "static-routes"));
        let hidden = fixture.store.get(&lab(), "damaged").map(drop);

        assert!(
            matches!(refused, Err(PresetError::Forbidden)),
            "{refused:?}"
        );
        assert!(matches!(hidden, Err(PresetError::NotFound)), "{hidden:?}");
        assert_eq!(fs::read(&path)?, b"{\"schema\":1}");
        drop(fixture.store.capture(
            &admin(),
            &source,
            request("damaged", "lab", "static-routes"),
        )?);
        assert_eq!(
            fixture.store.get(&lab(), "damaged")?.source_router(),
            Some("lab")
        );
        Ok(())
    }
}
