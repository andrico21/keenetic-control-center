//! Registry-wide verification coverage through real domain planners and converters.

mod support;

#[path = "verification_coverage/tests/administration.rs"]
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "test helpers assert the real planner contract"
)]
mod administration;
#[path = "verification_coverage/tests/execution.rs"]
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "async test helpers assert the real execution contract"
)]
mod execution;
#[path = "verification_coverage/tests/network.rs"]
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "test helpers assert the real planner contract"
)]
mod network;
#[path = "verification_coverage/tests/vpn.rs"]
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    reason = "test helpers propagate planner setup failures"
)]
mod vpn;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "integration assertions establish the verification contract"
)]
mod tests {
    use kcc_app::workflow::{CliChangeRequest, WorkflowError};
    use kcc_catalog::Risk;
    use kcc_domain::{DomainError, DomainId, registry, services, verification};

    use crate::{
        administration, execution, network,
        support::{Fixture, PROFILES, TestResult, toggle_service},
        vpn,
    };

    /// Checks the converter's actual expectations without manufacturing a verification list.
    pub(crate) fn checked(request: CliChangeRequest) -> TestResult {
        verification::require(&request)?;
        drop(request);
        Ok(())
    }

    /// Dropping a stateful planner's expectations must fail before router dispatch.
    #[tokio::test]
    async fn missing_verification_is_refused_before_dispatch() -> TestResult {
        for firmware in PROFILES {
            let fixture = Fixture::spawn(firmware).await?;
            let service = toggle_service(firmware);
            let plan = services::plan_service(fixture.context(), service, true)?;
            let mut request = services::change_request(&plan)?;
            request.verify.clear();
            let before = fixture.handle().request_count();
            assert!(matches!(
                verification::require(&request),
                Err(DomainError::Workflow(WorkflowError::VerificationFailed { field }))
                    if field == format!("service {service}")
            ));
            assert_eq!(fixture.handle().request_count(), before);
            fixture.shutdown().await?;
        }
        Ok(())
    }

    /// Every available state-changing registry operation reaches its real planner or executor.
    #[tokio::test]
    async fn registry_writes_require_verification_or_documented_action() -> TestResult {
        for firmware in PROFILES {
            let fixture = Fixture::spawn(firmware).await?;
            for domain in registry() {
                for operation in domain.write_ops {
                    if operation.risk == Risk::Read
                        || !operation.available(&fixture.context().catalog)
                    {
                        continue;
                    }
                    if let Some(reason) = operation.action_without_state() {
                        assert!(!reason.is_empty(), "action requires a reason");
                        continue;
                    }
                    let result = match domain.id {
                        DomainId::System
                        | DomainId::Services
                        | DomainId::KeenDns
                        | DomainId::Schedules
                        | DomainId::Logging
                        | DomainId::RouterUsers
                        | DomainId::Components => {
                            administration::check(fixture.context(), domain.id, operation.name)
                        }
                        DomainId::Wan
                        | DomainId::Wifi
                        | DomainId::Dns
                        | DomainId::Policies
                        | DomainId::Routing
                        | DomainId::Firewall => {
                            network::check(fixture.context(), domain.id, operation.name)
                        }
                        DomainId::VpnClients | DomainId::VpnServers => {
                            vpn::check(fixture.context(), domain.id, operation.name)
                        }
                        DomainId::Clients
                        | DomainId::Dhcp
                        | DomainId::Segments
                        | DomainId::Interfaces
                        | DomainId::Nat
                        | DomainId::Configuration
                        | DomainId::Mesh => {
                            execution::check(firmware, domain.id, operation.name).await
                        }
                        DomainId::Internet | DomainId::Diagnostics | DomainId::Storage | _ => {
                            Err("uncovered registry write".into())
                        }
                    };
                    result.map_err(|error| {
                        format!(
                            "{firmware} {:?}/{} ({}): {error}",
                            domain.id, operation.name, operation.catalog_path
                        )
                    })?;
                }
            }
            fixture.shutdown().await?;
        }
        Ok(())
    }
}
