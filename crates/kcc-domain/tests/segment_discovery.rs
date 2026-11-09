//! Segment discovery and deletion from fresh contexts.
extern crate alloc;

mod support;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "integration assertions define segment ownership contracts"
)]
mod tests {
    use alloc::sync::Arc;
    use core::net::Ipv4Addr;

    use kcc_app::{
        permissions::Permission,
        workflow::{CliChangeRequest, CliCommand as ValidatedCli},
    };
    use kcc_catalog::HttpMethod;
    use kcc_domain::{
        RouterCtx,
        segments::{self, SegmentSpec},
    };
    use serde_json::json;

    use crate::support::{Fixture, PROFILES, TestResult};

    /// Discovery reconstructs deletion ownership without retaining the creation receipt.
    // NOT cancel-safe: applies segment creation and deletion to an isolated router.
    #[tokio::test]
    async fn fresh_context_discovery_delete_restores_both_stores() -> TestResult {
        for firmware in PROFILES {
            let fixture = Fixture::spawn(firmware).await?;
            let settings = fixture.handle().settings_snapshot();
            let running = fixture.handle().running_config_text();
            let mut changes = fixture.changes().await?;
            drop(segments::create(&mut changes, fixture.context(), &spec()).await?);
            let fresh = RouterCtx::new(
                Arc::clone(&fixture.context().client),
                fixture.context().catalog.clone(),
            );

            let discovered = segments::read_segments(&fresh).await?;

            let [view] = discovered.as_slice() else {
                return Err("expected one owned segment".into());
            };
            assert!(view.complete);
            assert_eq!(view.vlan_id.value(), 23);
            assert_eq!(view.address, Some(Ipv4Addr::new(192, 0, 2, 129)));
            assert_eq!(
                view.access_point.as_deref(),
                Some("WifiMaster0/AccessPoint1")
            );
            assert_eq!(view.connection_policy.as_deref(), Some("SegmentPolicy23"));
            let summary = segments::delete_discovered(&mut changes, &fresh, view).await?;
            assert_eq!(summary.id, 23);
            assert_eq!(fixture.handle().settings_snapshot(), settings);
            assert_eq!(fixture.handle().running_config_text(), running);
            drop(changes);
            fixture.shutdown().await?;
        }
        Ok(())
    }

    /// Missing configured leaves produce a partial view that retains safe deletion ownership.
    // NOT cancel-safe: mutates an isolated router.
    #[tokio::test]
    async fn partial_segment_is_discoverable_and_deletable() -> TestResult {
        for firmware in PROFILES {
            let fixture = Fixture::spawn(firmware).await?;
            let running = fixture.handle().running_config_text();
            let mut changes = fixture.changes().await?;
            drop(segments::create(&mut changes, fixture.context(), &spec()).await?);
            let validated = fixture
                .context()
                .catalog
                .validate(
                    "ip nat",
                    HttpMethod::Post,
                    &json!({"interface":"Bridge23","no":true}),
                )
                .map_err(|_issues| "NAT fixture invalid")?;
            drop(
                changes
                    .apply_cli(CliChangeRequest::new(
                        vec![ValidatedCli::new(
                            "no ip nat Bridge23".to_owned(),
                            validated,
                        )],
                        Vec::new(),
                        Permission::Write,
                        json!({}),
                    ))
                    .await?,
            );

            let discovered = segments::read_segments(fixture.context()).await?;

            let [view] = discovered.as_slice() else {
                return Err("expected partial segment".into());
            };
            assert!(!view.complete);
            assert!(!view.nat);
            drop(segments::delete_discovered(&mut changes, fixture.context(), view).await?);
            assert_eq!(fixture.handle().running_config_text(), running);
            drop(changes);
            fixture.shutdown().await?;
        }
        Ok(())
    }

    /// Discovery does not claim similarly named pre-existing contexts without ownership.
    // NOT cancel-safe: creates an isolated fixture.
    #[tokio::test]
    async fn preexisting_contexts_are_not_claimed_or_overwritten() -> TestResult {
        for firmware in PROFILES {
            let fixture = Fixture::spawn(firmware).await?;
            let mut changes = fixture.changes().await?;
            let request = fixture
                .context()
                .catalog
                .validate("interface", HttpMethod::Post, &json!({"name":"Vlan23"}))
                .map_err(|_issues| "interface fixture invalid")?;
            drop(
                changes
                    .apply_cli(CliChangeRequest::new(
                        vec![ValidatedCli::new("interface Vlan23".to_owned(), request)],
                        Vec::new(),
                        Permission::Write,
                        json!({}),
                    ))
                    .await?,
            );
            let before = fixture.handle().running_config_text();

            let discovered = segments::read_segments(fixture.context()).await?;
            let refused = segments::create(&mut changes, fixture.context(), &spec()).await;

            assert!(
                discovered.is_empty(),
                "unmarked context must not be claimed"
            );
            assert!(matches!(refused, Err(segments::SegmentError::Domain(_))));
            assert_eq!(fixture.handle().running_config_text(), before);
            drop(changes);
            fixture.shutdown().await?;
        }
        Ok(())
    }

    /// Deletion preserves unrelated configuration added to an owned bridge.
    // NOT cancel-safe: mutates an isolated router.
    #[tokio::test]
    async fn unrelated_bridge_child_blocks_context_deletion() -> TestResult {
        for firmware in PROFILES {
            let fixture = Fixture::spawn(firmware).await?;
            let mut changes = fixture.changes().await?;
            drop(segments::create(&mut changes, fixture.context(), &spec()).await?);
            let views = segments::read_segments(fixture.context()).await?;
            let view = views.first().ok_or("segment missing")?;
            let validated = fixture
                .context()
                .catalog
                .validate(
                    "interface description",
                    HttpMethod::Post,
                    &json!({"description":"external"}),
                )
                .map_err(|_issues| "description invalid")?;
            drop(
                changes
                    .apply_cli(CliChangeRequest::new(
                        vec![ValidatedCli::new(
                            "interface Bridge23 description external".to_owned(),
                            validated,
                        )],
                        Vec::new(),
                        Permission::Write,
                        json!({}),
                    ))
                    .await?,
            );
            let before = fixture.handle().running_config_text();

            let result = segments::delete_discovered(&mut changes, fixture.context(), view).await;

            assert!(matches!(result, Err(segments::SegmentError::Domain(_))));
            assert_eq!(fixture.handle().running_config_text(), before);
            drop(changes);
            fixture.shutdown().await?;
        }
        Ok(())
    }

    /// Complete fixture with shared and newly introduced trunk contexts.
    fn spec() -> SegmentSpec {
        SegmentSpec::new(
            23,
            23,
            Ipv4Addr::new(192, 0, 2, 129),
            Ipv4Addr::new(255, 255, 255, 192),
            Ipv4Addr::new(192, 0, 2, 130),
            Ipv4Addr::new(192, 0, 2, 180),
            vec![
                "GigabitEthernet0/0".to_owned(),
                "GigabitEthernet0/4".to_owned(),
            ],
        )
        .with_access_point("WifiMaster0/AccessPoint1".to_owned())
        .with_connection_policy("SegmentPolicy23".to_owned())
    }
}
