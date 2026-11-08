//! An interrupted transient preset copy leaves no clear secret anywhere in the state dir.

extern crate alloc;

#[path = "support/state_scan.rs"]
mod state_scan;
#[path = "support/apply_fixture.rs"]
#[expect(
    dead_code,
    reason = "the shared apply fixture exposes migration helpers not needed by this suite"
)]
mod support;

#[cfg(test)]
mod tests {
    #![expect(
        clippy::missing_errors_doc,
        clippy::missing_panics_doc,
        clippy::panic_in_result_fn,
        reason = "integration assertions establish the secrets-at-rest contract"
    )]

    use alloc::sync::Arc;
    use core::error::Error;

    use kcc_app::audit::{Actor, ActorKind};
    use kcc_config::{config_text::parse, ns3};
    use kcc_migrate::{
        apply::{Applier, ApplyError},
        inventory::{InventoryClient, TargetInventory, source_version},
        planner::{Choices, MigrationMaps},
        presets::{
            apply::{PresetApplyOptions, PresetApplyRequest, request},
            groups::SettingsGroupEngine,
            model::{CaptureRequest, Preset, PresetSource, PresetSourceKind},
            plan::{PresetInput, PresetMode, plan},
        },
    };
    use kcc_testkit::{FaultInjection, model::Profile};
    use secrecy::{ExposeSecret as _, SecretString};

    use crate::{state_scan, support::Fixture};

    /// The dummy secrets one copy carries, all built at run time.
    struct Secrets {
        /// Decoded Wi-Fi pre-shared key.
        psk: String,
        /// The PSK's `ns3` encoding as it appears in the source config.
        encoded: String,
        /// A 44-character WireGuard private key.
        wireguard: String,
        /// The operator-supplied replacement password for router user `ops`.
        password: String,
    }

    impl Secrets {
        /// Builds fresh dummy values.
        fn new() -> Result<Self, Box<dyn Error>> {
            let psk = ["copy", "psk", "fixture"].join("-");
            let encoded = ns3::encode(&SecretString::from(psk.clone()))?;
            let wireguard = format!("{}{}=", "Kq".repeat(21), "w");
            let password = ["supplied", "router", "user", "pw"].join("_");
            Ok(Self {
                psk,
                encoded,
                wireguard,
                password,
            })
        }

        /// Source config holding a realm-bound user hash, an `ns3` PSK and a WireGuard key.
        fn source_text(&self) -> String {
            format!(
                "user ops\n password md5 {}\n!\ninterface WifiMaster0/AccessPoint9\n authentication wpa-psk ns3 {}\n!\ninterface Wireguard9\n wireguard private-key {}\n!\n",
                "ab".repeat(16),
                self.encoded,
                self.wireguard
            )
        }

        /// Labelled byte needles for the state scan.
        fn needles(&self) -> Vec<(String, Vec<u8>)> {
            vec![
                (
                    "ns3 blob".to_owned(),
                    format!("ns3 {}", self.encoded).into_bytes(),
                ),
                ("encoded psk".to_owned(), self.encoded.clone().into_bytes()),
                ("decoded psk".to_owned(), self.psk.clone().into_bytes()),
                (
                    "wireguard key".to_owned(),
                    self.wireguard.clone().into_bytes(),
                ),
                (
                    "supplied password".to_owned(),
                    self.password.clone().into_bytes(),
                ),
            ]
        }
    }

    /// A never-stored preset of the three secret-bearing groups, as `kcc copy` builds it.
    fn transient(secrets: &Secrets) -> Result<Preset, Box<dyn Error>> {
        let groups = ["router-users", "wifi", "vpn-clients"];
        let selection =
            SettingsGroupEngine::embedded()?.select(&parse(&secrets.source_text())?, &groups)?;
        Ok(Preset::captured(
            CaptureRequest::new(
                "copy".to_owned(),
                "Copy".to_owned(),
                String::new(),
                groups.map(str::to_owned).to_vec(),
                PresetSource::new(
                    PresetSourceKind::Router,
                    None,
                    "Keenetic Giga".to_owned(),
                    "4.3.0".to_owned(),
                    1_800_000_000,
                ),
                "tester".to_owned(),
            ),
            selection,
        ))
    }

    /// Interrupt a transient copy after its first line, then scan the whole state dir.
    #[tokio::test]
    async fn interrupted_transient_copy_leaves_no_clear_secret_on_disk()
    -> Result<(), Box<dyn Error>> {
        let fixture = Fixture::spawn(
            Profile::default(),
            FaultInjection::default().fail_parse_matching("private-key", 1),
        )
        .await?;
        let secrets = Secrets::new()?;
        let preset = transient(&secrets)?;
        let client = fixture
            .registry
            .bootstrap_client(&fixture.role, "target")
            .await?;
        let inventory = TargetInventory::collect(
            &InventoryClient::from_client(&client),
            Some(source_version("4.3.0")?),
        )
        .await?;
        let maps = MigrationMaps::default();
        let unsupplied = plan(
            &preset,
            &inventory,
            PresetMode::Merge,
            &maps,
            &Choices::default(),
        )?;
        assert!(
            unsupplied.items.iter().any(|item| item.needed_input
                == Some(PresetInput::RouterUserPassword {
                    user: "ops".to_owned()
                })),
            "the realm-bound hash must ask for a password: {unsupplied:?}"
        );
        let mut choices = Choices::default();
        drop(choices.new_passwords.insert(
            "ops".to_owned(),
            SecretString::from(secrets.password.clone()),
        ));
        let reviewed = plan(&preset, &inventory, PresetMode::Merge, &maps, &choices)?;
        let carried = reviewed
            .items
            .iter()
            .filter_map(|item| item.expose_command())
            .collect::<Vec<_>>()
            .join("\n");
        for (label, needle) in [
            ("password", &secrets.password),
            ("ns3", &secrets.encoded),
            ("wireguard", &secrets.wireguard),
        ] {
            assert!(carried.contains(needle.as_str()), "{label} not in the plan");
        }
        let mut input = PresetApplyRequest::new(
            Arc::clone(&fixture.workflow),
            fixture.audit.clone(),
            Actor::new(ActorKind::Cli, "operator".to_owned()),
            fixture.role.clone(),
            "target".to_owned(),
            preset,
            reviewed,
            inventory,
        );
        input.options = PresetApplyOptions::default().keep_wireguard_keys();

        let (_id, done) = Applier::start(&fixture.runner, request(input)?).await?;
        let applier = done.await??;
        assert_eq!(applier.report().failure, Some(ApplyError::Stopped));
        assert!(
            !applier.report().applied.is_empty(),
            "the copy must stop mid-apply, after its first line"
        );
        drop(applier);

        let root = fixture.state.dir();
        let scanned = state_scan::files(root)?;
        for area in ["audit", "jobs", "backups"] {
            assert!(
                scanned.iter().any(|file| file.starts_with(area)),
                "nothing scanned under {area}: {scanned:?}"
            );
        }
        let needles = secrets.needles();
        let borrowed = needles
            .iter()
            .map(|(label, bytes)| (label.as_str(), bytes.as_slice()))
            .collect::<Vec<_>>();
        assert_eq!(state_scan::hits(root, &borrowed)?, Vec::new());
        assert_eq!(
            ns3::decode(&secrets.encoded)?.expose_secret(),
            secrets.psk,
            "the decoded-psk needle is the blob's plaintext"
        );
        fixture.handle.shutdown().await?;
        Ok(())
    }
}
