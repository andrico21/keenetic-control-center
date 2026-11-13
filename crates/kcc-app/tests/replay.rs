//! Protected replay integration contracts.
extern crate alloc;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "integration assertions define replay safety contracts"
)]
mod tests {
    use alloc::sync::Arc;
    use core::error::Error;

    use kcc_app::{
        audit::{Actor, ActorKind, AuditLog, verify_chain},
        backups::BackupStore,
        permissions::{Permission, Role},
        persist::StateStore,
        registry::{ManagedRouterProfile, RouterRegistry},
        secrets::MasterKey,
        settings::OutboundConfig,
        workflow::{ChangeWorkflow, CliCommand, ReplayOutcome, ReplayPolicy},
    };
    use kcc_catalog::{Catalog, HttpMethod};
    use kcc_testkit::{DEFAULT_PASSWORD, FakeRouter, FaultInjection, model::Profile};
    use secrecy::SecretString;
    use serde_json::json;
    use tempfile::TempDir;
    use url::Url;

    /// Strict replay stops at the rejected line; permissive replay retains its error and continues.
    // NOT cancel-safe: fixture applies isolated router mutations.
    #[tokio::test]
    async fn replay_retains_partial_results_and_enforces_stop_policy() -> Result<(), Box<dyn Error>>
    {
        for (policy, expected) in [
            (
                ReplayPolicy::StopOnError,
                vec![ReplayOutcome::Applied, ReplayOutcome::Rejected],
            ),
            (
                ReplayPolicy::ContinueOnRejection,
                vec![
                    ReplayOutcome::Applied,
                    ReplayOutcome::Rejected,
                    ReplayOutcome::Applied,
                ],
            ),
        ] {
            let directory = TempDir::new()?;
            let (address, handle) = FakeRouter::builder(Profile::default())
                .faults(FaultInjection::default().fail_parse_matching("reject-me", 1))
                .build()?
                .serve(([127, 0, 0, 1], 0).into())
                .await?;
            let password_file =
                kcc_testkit::write_secret_file(directory.path(), "password", DEFAULT_PASSWORD)?;
            let state = StateStore::open(&directory.path().join("state"))?;
            let mut outbound = OutboundConfig::default();
            outbound.allow_loopback = true;
            let registry = Arc::new(RouterRegistry::new(state.clone(), &[], &outbound)?);
            let role = Role::new("admin".to_owned(), Permission::ALL, Vec::new());
            registry
                .create(
                    &role,
                    ManagedRouterProfile::new(
                        "router".to_owned(),
                        Url::parse(&format!("http://{address}"))?,
                        "admin".to_owned(),
                        password_file,
                    ),
                )
                .await?;
            let backups = Arc::new(BackupStore::new(
                state.clone(),
                MasterKey::from_bytes([7_u8; 32]),
            ));
            let workflow = ChangeWorkflow::new(
                state.clone(),
                Arc::clone(&registry),
                Arc::clone(&backups),
                AuditLog::spawn(&state)?,
            );
            let catalog = Catalog::for_router(&registry.poll_info("router").await?)?;
            let mut changes = workflow
                .begin(
                    "router",
                    Actor::new(ActorKind::Cli, "operator".to_owned()),
                    &role,
                    None,
                    false,
                )
                .await?;
            let commands = ["first-secret", "reject-me", "last-secret"]
                .into_iter()
                .map(|description| {
                    let validated = catalog
                        .validate(
                            "interface description",
                            HttpMethod::Post,
                            &json!({"description":description}),
                        )
                        .map_err(|_issues| "invalid fixture command")?;
                    Ok(CliCommand::secret(
                        validated,
                        SecretString::from(format!("interface Bridge9 description {description}")),
                    ))
                })
                .collect::<Result<Vec<_>, Box<dyn Error>>>()?;

            let result = changes.replay(&commands, policy).await?;

            assert_eq!(result.outcomes, expected);
            assert_eq!(result.completion, Ok(()));
            let expected_description = match policy {
                ReplayPolicy::StopOnError => "first-secret",
                ReplayPolicy::ContinueOnRejection => "last-secret",
                _ => return Err("unexpected policy".into()),
            };
            assert!(handle.running_config_text().contains(expected_description));
            assert!(!handle.startup_config_text().contains(expected_description));
            assert_eq!(backups.list("router")?.len(), 1);
            let events = verify_chain(state.dir())?;
            let event = events.last().ok_or("missing audit")?;
            assert_eq!(event.actor.id, "operator");
            assert_eq!(event.outcome, "partial_failure");
            let public = format!("{result:?} {}", serde_json::to_string(&events)?);
            for secret in ["first-secret", "reject-me", "last-secret"] {
                assert!(
                    !public.contains(secret),
                    "public results contain command text"
                );
            }
            drop(changes);
            handle.shutdown().await?;
        }
        Ok(())
    }
}
