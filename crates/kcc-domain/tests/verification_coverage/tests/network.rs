//! Real network planner inputs for the registry guard.

use core::net::Ipv4Addr;

use kcc_domain::{
    DomainError, DomainId, RouterCtx, dns, firewall, interfaces::ManagementVerdict, policies,
    routing, wan, wifi,
};

use crate::{administration::secret, support::TestResult, tests::checked};

/// Dispatches a registry write to its network planner.
pub(super) fn check(router: &RouterCtx, domain: DomainId, op: &str) -> TestResult {
    match domain {
        DomainId::Wan => wan_plan(router, op),
        DomainId::Wifi => wifi_plan(router, op),
        DomainId::Dns => dns_plan(router, op),
        DomainId::Policies => policy_plan(router, op),
        DomainId::Routing => {
            let plan = match op {
                "ipv4_route" => routing::change::plan_add_ipv4(
                    router,
                    &routing::model::Ipv4Route::network(
                        "198.51.100.0",
                        "255.255.255.0",
                        "192.0.2.1",
                    ),
                )?,
                "ipv6_route" => routing::change::plan_add_ipv6(
                    router,
                    &routing::model::Ipv6Route::via_gateway("2001:db8:67::/64", "2001:db8::1"),
                )?,
                _ => return Err("uncovered route operation".into()),
            };
            checked(routing::change::request(&plan)?)
        }
        DomainId::Firewall => {
            let plan = match op {
                "rule" => firewall::change::plan_add_rule(
                    router,
                    "Coverage67",
                    &firewall::model::Rule::new(
                        firewall::model::Action::Permit,
                        firewall::model::Protocol::Tcp,
                        "192.0.2.67",
                        "198.51.100.67",
                    ),
                )?,
                "binding" => firewall::change::plan_bind(
                    router,
                    "Bridge0",
                    "Coverage67",
                    firewall::model::Direction::In,
                    true,
                )?,
                _ => return Err("uncovered firewall operation".into()),
            };
            checked(firewall::change::request(&plan)?)
        }
        DomainId::System
        | DomainId::Internet
        | DomainId::Configuration
        | DomainId::Diagnostics
        | DomainId::Clients
        | DomainId::Dhcp
        | DomainId::Segments
        | DomainId::RouterUsers
        | DomainId::Nat
        | DomainId::Services
        | DomainId::Components
        | DomainId::Storage
        | DomainId::Schedules
        | DomainId::KeenDns
        | DomainId::Logging
        | DomainId::VpnClients
        | DomainId::VpnServers
        | DomainId::Interfaces
        | DomainId::Mesh
        | _ => Err("wrong network domain".into()),
    }
}

/// Covers all WAN registry entries with a real named-interface input.
fn wan_plan(router: &RouterCtx, op: &str) -> TestResult {
    let name = "PPPoE67".parse()?;
    let plan = match op {
        "create" => wan::plan_create(router, &name)?,
        "delete" => wan::plan_delete(router, &name)?,
        "address_static" => wan::plan_static_address(
            router,
            &name,
            wan::StaticAddress::new(
                Ipv4Addr::new(192, 0, 2, 67),
                Ipv4Addr::new(255, 255, 255, 0),
            ),
            ManagementVerdict::NotManagement,
        )?,
        "address_dhcp" => wan::plan_dhcp(router, &name, ManagementVerdict::NotManagement)?,
        "identity" => wan::plan_identity(router, &name, "coverage67")?,
        "password" => wan::plan_password(router, &name, secret())?,
        "connect_via" => wan::plan_connect_via(router, &name, &"ISP".parse()?)?,
        "priority" => wan::plan_priority(router, &name, 67)?,
        "mtu" => wan::plan_mtu(router, &name, 1_400)?,
        "default_route" => wan::plan_default_route(router, &name, true)?,
        _ => return Err("uncovered WAN operation".into()),
    };
    checked(wan::change_request(&name, &plan)?)
}

/// Covers radio and access-point planners, including protected PSK construction.
fn wifi_plan(router: &RouterCtx, op: &str) -> TestResult {
    let name = "WifiMaster0/AccessPoint0".parse()?;
    let plan = match op {
        "ssid" => wifi::plan_ssid(router, &name, "coverage67")?,
        "wpa_psk" => wifi::plan_wpa_psk(router, &name, secret())?,
        "encryption_enable" => wifi::plan_encryption(router, &name, wifi::Encryption::Enable)?,
        "encryption_wpa2" => wifi::plan_encryption(router, &name, wifi::Encryption::Wpa2)?,
        "encryption_wpa3" => wifi::plan_encryption(router, &name, wifi::Encryption::Wpa3)?,
        "hide_ssid" => wifi::plan_hide_ssid(router, &name, true)?,
        "up" => wifi::plan_up(router, &name, true)?,
        "schedule" => wifi::plan_schedule(router, &name, "Schedule0")?,
        "channel" => wifi::plan_channel(router, &name, "auto")?,
        "channel_width" => wifi::plan_channel_width(router, &name, "20")?,
        "power" => wifi::plan_power(router, &name, 50)?,
        "country_code" => wifi::plan_country_code(router, &name, "DE")?,
        "band_steering" => wifi::plan_band_steering(router, &name, true)?,
        _ => return Err("uncovered Wi-Fi operation".into()),
    };
    checked(wifi::change_request(&name, &plan)?)
}

/// Covers each DNS planner family with its typed input.
fn dns_plan(router: &RouterCtx, op: &str) -> TestResult {
    let change = match op {
        "tls_upstream" => dns::DnsChange::TlsUpstream(dns::TlsUpstream::new("192.0.2.67")),
        "https_upstream" => dns::DnsChange::HttpsUpstream(dns::HttpsUpstream::new(
            "https://resolver.invalid/dns-query",
        )),
        "filter_engine" => dns::DnsChange::FilterEngine(dns::FilterEngine::Interceptor),
        "filter_profile" => dns::DnsChange::FilterProfile {
            name: "Coverage67".to_owned(),
        },
        "intercept" => dns::DnsChange::Intercept { enabled: true },
        "rebind_protect" => dns::DnsChange::RebindProtect(dns::RebindProtection::Strict),
        "max_ttl" => dns::DnsChange::MaxTtl(Some(67)),
        "route" => dns::DnsChange::Route(dns::DnsRoute::new("Coverage67")),
        "name_server" => dns::DnsChange::NameServer {
            address: "192.0.2.67".to_owned(),
        },
        "static_host" => dns::DnsChange::StaticHost {
            domain: "coverage.invalid".to_owned(),
            address: "192.0.2.67".to_owned(),
        },
        "fqdn_group" => dns::DnsChange::FqdnGroup {
            name: "Coverage67".to_owned(),
        },
        "nextdns_assign" => dns::DnsChange::NextDnsInterface {
            interface: "Bridge0".to_owned(),
            token: 67,
        },
        _ => return Err("uncovered DNS operation".into()),
    };
    let planned = dns::plan_change(router, &change);
    if op == "rebind_protect" {
        assert!(
            matches!(planned, Err(DomainError::Validation { issues: _ })),
            "the catalog lacks the planner's mode argument; it must refuse before dispatch"
        );
        return Ok(());
    }
    checked(dns::change_request(&planned?)?)
}

/// Covers policy leaf and context planners.
fn policy_plan(router: &RouterCtx, op: &str) -> TestResult {
    use policies::{
        change::plan,
        model::{PolicyPermit, PolicyRateLimit, PolicyRoute, RateDirection},
    };
    let name = "Coverage67";
    let operation = match op {
        "policy" => plan::create(router, name)?,
        "description" => plan::description(router, name, Some("coverage67"))?,
        "permit" => plan::permit(router, name, &PolicyPermit::new("ISP"), true)?,
        "multipath" => plan::multipath(router, name, true)?,
        "route" => plan::route(
            router,
            name,
            &PolicyRoute::host("198.51.100.67", "192.0.2.1"),
            true,
        )?,
        "rate_limit_input" => plan::rate_limit(
            router,
            name,
            &PolicyRateLimit::fixed("ISP", RateDirection::Input, 67),
            true,
        )?,
        "rate_limit_output" => plan::rate_limit(
            router,
            name,
            &PolicyRateLimit::fixed("ISP", RateDirection::Output, 67),
            true,
        )?,
        "standalone" => plan::standalone(router, name, true)?,
        _ => return Err("uncovered policy operation".into()),
    };
    checked(policies::change::render::request(&operation)?)
}
