//! Every line a planner sends renders the request it was planned and validated as.

#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests use assertions and a boxed error result"
)]

mod support;

use core::net::Ipv4Addr;

use kcc_app::workflow::CliChangeRequest;
use kcc_catalog::ValidatedRequest;
use kcc_config::config_text::{Token, flatten, parse};
use kcc_domain::{
    dhcp,
    dns::{self, DnsChange},
    firewall::{
        self,
        model::{Action, Protocol, Rule},
        rule_list::ListedRule,
    },
    interfaces::{self, ManagementVerdict},
    routing::{change as routing, model::Ipv6Route},
    segments::{self, SegmentSpec},
    wifi,
};
use kcc_rci::ObjectName;

use crate::support::{Fixture, PROFILES, TestResult};

/// The words of one CLI line as the router reads them.
fn words(line: &str) -> TestResult<Vec<String>> {
    let ast = parse(line)?;
    let [command] = <[_; 1]>::try_from(flatten(&ast)).map_err(|_lines| "not one line")?;
    command
        .tokens
        .into_iter()
        .map(|token| {
            if let Token::Word(word) = token {
                Ok(word)
            } else {
                Err("not a plain word".into())
            }
        })
        .collect()
}

/// Whether `line` renders `request`.
fn renders(request: &ValidatedRequest, line: &str) -> TestResult<bool> {
    let words = words(line)?;
    Ok(request.renders_cli(&words.iter().map(String::as_str).collect::<Vec<_>>()))
}

/// Every line of `request` renders the request it carries.
fn assert_renders(request: &CliChangeRequest) -> TestResult<Vec<String>> {
    let mut lines = Vec::new();
    for command in &request.commands {
        let line = command.expose_for_send()?.to_string();
        assert!(
            renders(command.validated(), &line)?,
            "{line} does not render {} {}",
            command.validated().path,
            command.validated().value()
        );
        lines.push(line);
    }
    Ok(lines)
}

/// Sends `request` and checks that the router received its last line as rendered.
async fn assert_sent_as_rendered(fixture: &Fixture, request: CliChangeRequest) -> TestResult {
    let lines = assert_renders(&request)?;
    let before = fixture.handle().request_log().len();
    let mut changes = fixture.changes().await?;
    drop(changes.apply_cli(request).await?);
    drop(changes);
    let sent = fixture
        .handle()
        .request_log()
        .iter()
        .skip(before)
        .filter_map(|record| record.command().map(str::to_owned))
        .collect::<Vec<_>>();
    assert!(sent.contains(lines.last().ok_or("no line")?), "{sent:?}");
    Ok(())
}

/// The commands the router received after `before` requests.
fn sent_since(fixture: &Fixture, before: usize) -> Vec<String> {
    fixture
        .handle()
        .request_log()
        .iter()
        .skip(before)
        .filter_map(|record| record.command().map(str::to_owned))
        .collect()
}

/// Each request of a plan is rendered by one of the lines the router received.
fn assert_each_sent(requests: &[ValidatedRequest], sent: &[String]) -> TestResult {
    for request in requests {
        let mut found = false;
        for line in sent {
            found |= renders(request, line)?;
        }
        assert!(
            found,
            "no line sent for {} {}: {sent:?}",
            request.path,
            request.value()
        );
    }
    Ok(())
}

/// B-08: a segment's lines, its cleanup lines included, are the lines of its planned
/// requests, so the plan shown and audited is what reaches the router.
#[tokio::test]
async fn segment_lines_render_their_planned_requests() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;
        let spec = SegmentSpec::new(
            23,
            23,
            Ipv4Addr::new(192, 0, 2, 129),
            Ipv4Addr::new(255, 255, 255, 192),
            Ipv4Addr::new(192, 0, 2, 130),
            Ipv4Addr::new(192, 0, 2, 180),
            // The router log keeps only the last line of a batch, and a trunk step's
            // batch ends with its port cleanup: ports are left out here.
            Vec::new(),
        )
        .with_access_point("WifiMaster0/AccessPoint1".to_owned())
        .with_connection_policy("SegmentPolicy23".to_owned());
        let planned_create = segments::plan_create(fixture.context(), &spec).await?;
        let planned_delete = segments::plan_delete(fixture.context(), &spec).await?;
        let mut changes = fixture.changes().await?;

        let before_create = fixture.handle().request_log().len();
        let created = segments::create(&mut changes, fixture.context(), &spec).await?;
        assert_each_sent(
            &planned_create.requests,
            &sent_since(&fixture, before_create),
        )?;
        let before_delete = fixture.handle().request_log().len();
        segments::delete(&mut changes, fixture.context(), created).await?;
        assert_each_sent(
            &planned_delete.requests,
            &sent_since(&fixture, before_delete),
        )?;

        drop(changes);
        fixture.shutdown().await?;
    }
    Ok(())
}

/// B-08: disabling an interface sends `down` with the request of `down`.
#[tokio::test]
async fn interface_down_renders_its_request() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;
        let name = ObjectName::try_from("WifiMaster0/AccessPoint1".to_owned())?;
        let interface =
            interfaces::plan_down(fixture.context(), &name, ManagementVerdict::NotManagement)?;
        assert_sent_as_rendered(&fixture, interfaces::change_request(&name, &interface)?).await?;
        let access_point = wifi::plan_up(fixture.context(), &name, false).await?;
        assert_sent_as_rendered(&fixture, wifi::change_request(&name, &access_point)?).await?;
        fixture.shutdown().await?;
    }
    Ok(())
}

/// B-08: a static lease line carries the host and the address its request names.
#[tokio::test]
async fn static_lease_line_renders_its_request() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;
        let pool = dhcp::model::PoolConfig::new(
            "Pool23".to_owned(),
            Ipv4Addr::new(192, 0, 2, 80),
            Ipv4Addr::new(192, 0, 2, 120),
        )
        .with_interface("Bridge0".to_owned())
        .with_enabled(true);
        let mut changes = fixture.changes().await?;
        let pool_plan = dhcp::plan_pool(fixture.context(), &pool)?;
        drop(dhcp::apply(&mut changes, fixture.context(), &pool_plan).await?);
        let lease = dhcp::plan_static_lease(
            fixture.context(),
            "02:00:00:00:10:aa".parse()?,
            Ipv4Addr::new(192, 0, 2, 99),
        )
        .await?;

        let before = fixture.handle().request_log().len();
        drop(dhcp::apply(&mut changes, fixture.context(), &lease).await?);

        assert_each_sent(&lease.requests, &sent_since(&fixture, before))?;
        drop(changes);
        fixture.shutdown().await?;
    }
    Ok(())
}

/// B-08: a filter-profile description line and an IPv6 route line follow the catalog
/// grammar of the request they carry.
#[tokio::test]
async fn dns_description_and_ipv6_route_render_their_requests() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;
        let described = dns::plan_change(
            fixture.context(),
            &DnsChange::FilterProfileDescription {
                name: "kids".to_owned(),
                description: "Streaming services".to_owned(),
            },
        )?;
        drop(assert_renders(&dns::change_request(&described)?)?);
        let route = Ipv6Route::via_gateway("2001:db8:7::/64", "2001:db8::1").on_interface("ISP");
        let planned = routing::plan_add_ipv6(fixture.context(), &route)?;
        assert_sent_as_rendered(&fixture, routing::request(&planned)?).await?;
        fixture.shutdown().await?;
    }
    Ok(())
}

/// B-08, D-10, W3-08: moving a firewall rule goes through the domain's order planner; the
/// line names the position its validated `new-index` carries, and the move applies.
#[tokio::test]
async fn firewall_order_renders_its_request() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;
        let mut changes = fixture.changes().await?;
        let rules = ["198.51.100.20", "198.51.100.21"]
            .map(|destination| Rule::new(Action::Permit, Protocol::Tcp, "192.0.2.10", destination));
        for rule in &rules {
            let added = firewall::change::plan_add_rule(fixture.context(), "OrderAcl", rule)?;
            drop(firewall::change::apply(&mut changes, fixture.context(), &added).await?);
        }
        let listed = firewall::read::configured_list(fixture.context(), "OrderAcl").await?;
        let first = listed.first().ok_or("rule was not read back")?;

        let planned = firewall::change::plan_order_rule(fixture.context(), "OrderAcl", first, 1)?;
        let request = firewall::change::request(&planned)?;

        assert_eq!(
            assert_renders(&request)?,
            ["access-list OrderAcl rule 0 order 1"]
        );
        let [command] = request.commands.as_slice() else {
            return Err("one command".into());
        };
        assert_eq!(
            command.validated().value(),
            &serde_json::json!({"index":0_u32,"new-index":1_u32})
        );
        drop(firewall::change::apply(&mut changes, fixture.context(), &planned).await?);
        let moved = firewall::read::configured_list(fixture.context(), "OrderAcl").await?;
        assert_eq!(
            moved
                .get(1)
                .and_then(ListedRule::structured)
                .map(|found| &found.rule),
            rules.first()
        );
        drop(changes);
        fixture.shutdown().await?;
    }
    Ok(())
}
