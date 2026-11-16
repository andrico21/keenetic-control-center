//! Real administration planner inputs for the registry guard.

use kcc_domain::{
    DomainId, RouterCtx, components, keendns, logging, router_users, schedules, services, system,
};
use secrecy::SecretString;

use crate::{support::TestResult, tests::checked};

/// Builds a runtime-owned dummy credential.
pub(super) fn secret() -> SecretString {
    SecretString::from(["coverage", "credential", "67"].join("-"))
}

/// Dispatches each registry entry to its actual planner and conversion function.
pub(super) fn check(router: &RouterCtx, domain: DomainId, op: &str) -> TestResult {
    match domain {
        DomainId::System => system_plan(router, op),
        DomainId::Services => {
            let plan = match op {
                "set_service" => {
                    let service = if router.catalog.lookup("service iperf3").is_some() {
                        "iperf3"
                    } else {
                        "udpxy"
                    };
                    services::plan_service(router, service, true)?
                }
                "management_port" => {
                    services::plan_port(router, services::ManagementListener::Http, own(router)?)?
                }
                "management_security_level" => services::plan_security_level(
                    router,
                    services::ManagementListener::Ssh,
                    services::SecurityLevel::Protected,
                )?,
                "http_ssl" => {
                    services::plan_http_ssl(router, services::HttpSslSetting::Enable(true))?
                }
                _ => return Err("uncovered service operation".into()),
            };
            checked(services::change_request(&plan)?)
        }
        DomainId::KeenDns => {
            let plan = match op {
                "book_name" => keendns::plan_book_name(router, "coverage67", "keenetic.link")?,
                "drop_name" => keendns::plan_drop_name(router, "coverage67", "keenetic.link")?,
                "proxy" => keendns::plan_proxy(router, "coverage67", true)?,
                "proxy_upstream" => {
                    keendns::plan_proxy_upstream(router, "coverage67", "http", "192.0.2.67", 8_080)?
                }
                "cloud_security_level" => keendns::plan_cloud_security_level(
                    router,
                    keendns::RemoteSecurityLevel::Private,
                )?,
                _ => return Err("uncovered KeenDNS operation".into()),
            };
            checked(keendns::change_request(&plan)?)
        }
        DomainId::Schedules => {
            let plan = match op {
                "create" => schedules::plan_create(router, "coverage67")?,
                "description" => schedules::plan_description(router, "coverage67", "night")?,
                "action" => schedules::plan_action(
                    router,
                    "coverage67",
                    schedules::ActionTime::new(schedules::ScheduleAction::Start, 30, 8, 1),
                )?,
                _ => return Err("uncovered schedule operation".into()),
            };
            checked(schedules::change_request(&plan)?)
        }
        DomainId::Logging => {
            let plan = match op {
                "server" => logging::plan_server(router, "192.0.2.67", Some(514), true)?,
                "reduction" => logging::plan_reduction(router, true)?,
                "suppress" => logging::plan_suppress(router, "Test67", true)?,
                _ => return Err("uncovered logging operation".into()),
            };
            checked(logging::change_request(&plan)?)
        }
        DomainId::RouterUsers => {
            let plan = match op {
                "create" => router_users::plan_create(router, "coverage67", &["http"])?,
                "set_tag" => router_users::plan_tag(router, "coverage67", "http", true)?,
                "set_password" => {
                    router_users::plan_password(router, "coverage67", "admin", secret())?
                }
                "delete" => router_users::plan_delete(router, "coverage67", "admin")?,
                _ => return Err("uncovered account operation".into()),
            };
            checked(router_users::change_request(&plan)?)
        }
        DomainId::Components => component_plan(router, op),
        DomainId::Internet
        | DomainId::Configuration
        | DomainId::Diagnostics
        | DomainId::Clients
        | DomainId::Dhcp
        | DomainId::Segments
        | DomainId::Routing
        | DomainId::Policies
        | DomainId::Nat
        | DomainId::Firewall
        | DomainId::Storage
        | DomainId::Dns
        | DomainId::VpnClients
        | DomainId::VpnServers
        | DomainId::Interfaces
        | DomainId::Wan
        | DomainId::Wifi
        | DomainId::Mesh
        | _ => Err("wrong administration domain".into()),
    }
}

/// Checks update policy and staging planners.
fn component_plan(router: &RouterCtx, op: &str) -> TestResult {
    let plan = match op {
        "check_update" => components::plan_check_update(router)?,
        "install" => components::plan_queue(router, components::QueueAction::Install, "wireguard")?,
        "remove" => components::plan_queue(router, components::QueueAction::Remove, "wireguard")?,
        "auto_update_channel" => components::plan_auto_update_channel(router, "stable")?,
        "auto_update_schedule" => components::plan_auto_update_schedule(router, "coverage67")?,
        _ => return Err("uncovered component operation".into()),
    };
    checked(components::change_request(&plan)?)
}

/// Checks structured system requests from their actual planners.
fn system_plan(router: &RouterCtx, op: &str) -> TestResult {
    let plan = match op {
        "hostname" => system::plan_hostname(router, "coverage67")?,
        "domainname" => system::plan_domainname(router, "coverage.invalid")?,
        "description" => system::plan_description(router, "coverage67")?,
        "timezone" => system::plan_timezone(router, "UTC")?,
        "ntp_server" => system::plan_ntp_server(router, "192.0.2.67")?,
        "ntp_master" => system::plan_ntp_master(router, true)?,
        "ntp_sync_period" => system::plan_ntp_sync_period(router, 67)?,
        _ => return Err("uncovered system operation".into()),
    };
    assert!(
        !system::change_request(&plan)?.verify.is_empty(),
        "system converter lost verification"
    );
    Ok(())
}

/// The port of the listener kcc reaches the router on; moving it is refused.
fn own(router: &RouterCtx) -> TestResult<u16> {
    Ok(router
        .client
        .router_url()
        .port()
        .ok_or("origin without a port")?)
}
