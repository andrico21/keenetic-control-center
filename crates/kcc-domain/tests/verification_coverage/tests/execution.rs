//! Registry coverage for domains that own their protected execution path.

use core::net::Ipv4Addr;

use kcc_app::workflow::{ChangeResult, ChangeSet, WorkflowError};
use kcc_domain::{
    DomainError, DomainId, RouterCtx, clients,
    configuration::{SafetyMode, SafetyNet, read_last_change},
    dhcp,
    dhcp::model::PoolConfig,
    interfaces, mesh, nat, segments, system,
};
use kcc_testkit::{FaultInjection, model::Firmware};
use serde_json::json;

use crate::{
    support::{Fixture, TestResult},
    tests::checked,
};

/// Exercises public apply paths where the CLI converter is intentionally private.
pub(super) async fn check(firmware: Firmware, domain: DomainId, op: &str) -> TestResult {
    if domain == DomainId::Configuration {
        return configuration(firmware, op).await;
    }
    let faults = if domain == DomainId::Dhcp && op == "static_lease" {
        FaultInjection::default().silent_noop_path("ip dhcp host 02:00:00:00:67:01 192.0.2.67")
    } else {
        FaultInjection::default().silent_noop_path("parse")
    };
    let fixture = Fixture::spawn_with_faults(firmware, faults).await?;
    let router = fixture.context();
    let mut changes = fixture.changes().await?;
    match domain {
        DomainId::Clients => {
            client_write(&mut changes, router, op).await?;
        }
        DomainId::Dhcp => {
            dhcp_write(&mut changes, router, op).await?;
        }
        DomainId::Interfaces => {
            interface_write(&mut changes, router, op).await?;
        }
        DomainId::Nat => {
            let plan = match op {
                "interface" => nat::change::plan_add_interface(router, "Coverage67")?,
                "forward" => nat::change::plan_add_forward(
                    router,
                    &nat::model::PortForward::to_address(
                        nat::model::Protocol::Tcp,
                        "ISP",
                        8_067,
                        "192.0.2.67",
                    ),
                )?,
                _ => return Err("uncovered NAT operation".into()),
            };
            let result = nat::change::apply(&mut changes, router, &plan).await;
            assert!(
                matches!(
                    result,
                    Err(DomainError::Workflow(WorkflowError::VerificationFailed {
                        field: _
                    }))
                ),
                "NAT no-op escaped workflow verification: {result:?}"
            );
        }
        DomainId::Mesh => {
            if op != "acquire" {
                return Err("uncovered mesh operation".into());
            }
            checked(mesh::change_request(&mesh::plan_acquire(
                router,
                "coverage67",
            )?)?)?;
        }
        DomainId::Segments => {
            drop(changes);
            fixture.shutdown().await?;
            return segment(firmware, op).await;
        }
        DomainId::System
        | DomainId::Internet
        | DomainId::Configuration
        | DomainId::Diagnostics
        | DomainId::RouterUsers
        | DomainId::Routing
        | DomainId::Policies
        | DomainId::Firewall
        | DomainId::Services
        | DomainId::Components
        | DomainId::Storage
        | DomainId::Schedules
        | DomainId::KeenDns
        | DomainId::Logging
        | DomainId::Dns
        | DomainId::VpnClients
        | DomainId::VpnServers
        | DomainId::Wan
        | DomainId::Wifi
        | _ => return Err("wrong execution domain".into()),
    }
    drop(changes);
    fixture.shutdown().await
}

/// Checks interface planner expectations and their protected application.
async fn interface_write(changes: &mut ChangeSet, router: &RouterCtx, op: &str) -> TestResult {
    let target = if op == "up" { "Ethernet67" } else { "Bridge0" }.parse()?;
    let plan = match op {
        "up" => interfaces::plan_up(router, &target)?,
        "down" => interfaces::plan_down(
            router,
            &target,
            interfaces::ManagementVerdict::NotManagement,
        )?,
        "description" => interfaces::plan_description(router, &target, "coverage67")?,
        "security_level" => interfaces::plan_security_level(
            router,
            &target,
            interfaces::SecurityLevel::Public,
            interfaces::ManagementVerdict::NotManagement,
        )?,
        _ => return Err("uncovered interface operation".into()),
    };
    assert!(
        !plan.verify.is_empty(),
        "interface planner lost verification"
    );
    let result = interfaces::apply(changes, router, &target, plan, true).await;
    assert!(result.is_err(), "interface no-op escaped verification");
    Ok(())
}

/// Proves segment create rejects a no-op and delete verifies its real composed plan.
async fn segment(firmware: Firmware, op: &str) -> TestResult {
    let faults = if op == "create" {
        FaultInjection::default().silent_noop_path("parse")
    } else {
        FaultInjection::default()
    };
    let fixture = Fixture::spawn_with_faults(firmware, faults).await?;
    let spec = segments::SegmentSpec::new(
        67,
        67,
        Ipv4Addr::new(192, 0, 2, 1),
        Ipv4Addr::new(255, 255, 255, 0),
        Ipv4Addr::new(192, 0, 2, 67),
        Ipv4Addr::new(192, 0, 2, 70),
        Vec::new(),
    );
    let mut changes = fixture.changes().await?;
    match op {
        "create" => assert!(
            segments::create(&mut changes, fixture.context(), &spec)
                .await
                .is_err(),
            "segment no-op escaped verification"
        ),
        "delete" => {
            let receipt = segments::create(&mut changes, fixture.context(), &spec).await?;
            segments::delete(&mut changes, fixture.context(), receipt).await?;
        }
        _ => return Err("uncovered segment operation".into()),
    }
    drop(changes);
    fixture.shutdown().await
}

/// Exercises save/commit state transitions and the native timer's no-op rejection.
async fn configuration(firmware: Firmware, op: &str) -> TestResult {
    let faulted = matches!(op, "fail_safe_arm" | "fail_safe_keep_alive");
    let faults = if faulted {
        FaultInjection::default()
            .silent_noop_path("system configuration fail-safe timer reboot 300")
            .silent_noop_path("system configuration fail-safe keep-alive")
    } else {
        FaultInjection::default()
    };
    let fixture = Fixture::spawn_with_faults(firmware, faults).await?;
    let mut changes = fixture.changes().await?;
    match op {
        "save" | "fail_safe_commit" => {
            let plan = system::plan_description(fixture.context(), "coverage67")?;
            let _: ChangeResult = changes.apply(system::change_request(&plan)?).await?;
            if op == "save" {
                changes.save().await?;
            } else {
                changes.commit().await?;
            }
            assert_eq!(
                read_last_change(fixture.context()).await?.unsaved,
                Some(false),
                "explicit persistence must clear the unsaved state"
            );
        }
        "fail_safe_arm" => {
            let result = SafetyNet::arm(
                &mut changes,
                fixture.context(),
                SafetyMode::Router,
                300,
                SafetyNet::CONTROL_PERMISSION,
            )
            .await;
            assert!(
                matches!(result, Err(WorkflowError::VerificationFailed { field: _ })),
                "timer no-op escaped verification: {result:?}"
            );
        }
        "fail_safe_keep_alive" => {
            let result = SafetyNet::keep_alive(
                &mut changes,
                fixture.context(),
                SafetyNet::CONTROL_PERMISSION,
            )
            .await;
            assert!(
                matches!(result, Err(WorkflowError::VerificationFailed { field: _ })),
                "timer no-op escaped verification: {result:?}"
            );
        }
        _ => return Err("uncovered configuration operation".into()),
    }
    drop(changes);
    fixture.shutdown().await
}

/// Exercises client plans through their real host-aware apply path.
async fn client_write(changes: &mut ChangeSet, router: &RouterCtx, op: &str) -> TestResult {
    let client: clients::Client =
        serde_json::from_value(json!({"mac":"02:00:00:00:67:01","registered":false}))?;
    let plan = match op {
        "register" => clients::plan_register(router, "02:00:00:00:67:01", "coverage67")?,
        "remove" => clients::plan_remove(router, "02:00:00:00:10:01")?,
        "access" => clients::plan_access(router, &client, "coverage67", clients::Access::Deny)?,
        "schedule" => clients::plan_schedule(router, &client, "coverage67", "Schedule0")?,
        "policy" => clients::plan_policy(router, &client, "coverage67", "Policy0")?,
        "priority" => clients::plan_priority(router, &client, "coverage67", 3)?,
        "default_policy" => clients::plan_default_policy(
            router,
            clients::PolicySelection::Access(clients::Access::Deny),
        )?,
        "interface_policy" => clients::plan_interface_policy(
            router,
            "Bridge0",
            clients::PolicySelection::Access(clients::Access::Deny),
        )?,
        _ => return Err("uncovered client operation".into()),
    };
    let result = clients::apply(changes, router, &plan).await;
    assert!(
        matches!(result, Err(WorkflowError::VerificationFailed { field: _ })),
        "client no-op escaped verification: {result:?}"
    );
    Ok(())
}

/// Supplies a real bound pool before exercising static-lease verification.
async fn dhcp_write(changes: &mut ChangeSet, router: &RouterCtx, op: &str) -> TestResult {
    let pool = PoolConfig::new(
        "Coverage67".to_owned(),
        Ipv4Addr::new(192, 0, 2, 67),
        Ipv4Addr::new(192, 0, 2, 70),
    )
    .with_interface("Bridge0".to_owned());
    if op == "static_lease" {
        drop(dhcp::apply(changes, router, &dhcp::plan_pool(router, &pool)?).await?);
    }
    let plan = match op {
        "pool" => dhcp::plan_pool(router, &pool)?,
        "static_lease" => {
            dhcp::plan_static_lease(router, "02:00:00:00:67:01", Ipv4Addr::new(192, 0, 2, 67))
                .await?
        }
        _ => return Err("uncovered DHCP operation".into()),
    };
    let result = dhcp::apply(changes, router, &plan).await;
    assert!(
        matches!(result, Err(WorkflowError::VerificationFailed { field: _ })),
        "DHCP no-op escaped verification: {result:?}"
    );
    Ok(())
}
