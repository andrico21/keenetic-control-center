//! Firewall reads of the running configuration: rule properties, rules kept as stored,
//! IPv6 lists and interface bindings.

#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests use assertions and a boxed error result"
)]

mod support;

use kcc_domain::firewall::{
    lists::{Binding, Firewall},
    model::{Action, Direction, Protocol},
    read,
};

use crate::support::{Fixture, PROFILES, TestResult};

/// Sends `lines` to the router of `fixture`, then reads its firewall.
async fn seeded(fixture: &Fixture, lines: &[&str]) -> TestResult<Firewall> {
    for line in lines {
        drop(fixture.context().client.parse(line).await?);
    }
    Ok(read::firewall(fixture.context()).await?)
}

#[tokio::test]
async fn rule_properties_are_read_by_rule_index() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;
        let firewall = seeded(
            &fixture,
            &[
                "access-list WebAcl permit tcp 192.0.2.10 255.255.255.255 198.51.100.20 255.255.255.255 port eq 443",
                "access-list WebAcl deny udp 192.0.2.0 255.255.255.0 203.0.113.5 255.255.255.255",
                "access-list WebAcl rule 1 disable",
                "access-list WebAcl rule 1 schedule Schedule0",
                "access-list WebAcl rule 0 description web",
            ],
        )
        .await?;

        let list = firewall.list("WebAcl").ok_or("missing WebAcl")?;
        let first = list.entry(0).ok_or("missing rule 0")?;
        assert!(!first.disabled());
        assert_eq!(first.description(), Some("web"));
        assert_eq!(first.schedule(), None);
        let second = list.entry(1).ok_or("missing rule 1")?;
        assert!(second.disabled());
        assert_eq!(second.description(), None);
        assert_eq!(second.schedule(), Some("Schedule0"));
        let form = second.rule().form().ok_or("structured rule")?;
        assert_eq!(form.action(), Action::Deny);
        assert_eq!(form.protocol(), Some(Protocol::Udp));
        assert_eq!(form.source().mask(), "255.255.255.0");
        let configured = second.configured().ok_or("planner identity")?;
        assert_eq!((configured.index, configured.disabled), (1, true));
        fixture.shutdown().await?;
    }
    Ok(())
}

#[tokio::test]
async fn a_rule_in_another_form_keeps_its_stored_words() -> TestResult {
    let stored =
        "permit tcp 192.0.2.10 255.255.255.255 port range 1000 2000 198.51.100.20 255.255.255.255";
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;
        let firewall = seeded(&fixture, &[&format!("access-list WebAcl {stored}")]).await?;

        let entry = firewall
            .list("WebAcl")
            .and_then(|list| list.entry(0))
            .ok_or("missing rule")?;
        assert_eq!(entry.rule().text(), stored);
        assert!(entry.rule().form().is_none());
        assert!(entry.configured().is_none());
        fixture.shutdown().await?;
    }
    Ok(())
}

#[tokio::test]
async fn ipv6_lists_are_read_apart_from_ipv4_lists() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;
        let firewall = seeded(
            &fixture,
            &[
                "ipv6 access-list V6Acl permit tcp 2001:db8::1 2001:db8::2",
                "ipv6 access-list V6Acl deny ip any any",
            ],
        )
        .await?;

        assert!(firewall.list("V6Acl").is_none());
        let list = firewall
            .ipv6()
            .iter()
            .find(|list| list.name() == "V6Acl")
            .ok_or("missing V6Acl")?;
        let words: Vec<String> = list
            .entries()
            .iter()
            .map(|entry| entry.rule().text())
            .collect();
        assert_eq!(
            words,
            ["permit tcp 2001:db8::1 2001:db8::2", "deny ip any any"]
        );
        fixture.shutdown().await?;
    }
    Ok(())
}

#[tokio::test]
async fn bindings_are_read_per_interface_and_direction() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;
        let firewall = seeded(
            &fixture,
            &[
                "access-list WebAcl deny tcp 192.0.2.10 255.255.255.255 198.51.100.20 255.255.255.255",
                "access-list GuestAcl deny udp 192.0.2.0 255.255.255.0 203.0.113.5 255.255.255.255",
                "interface ISP ip access-group WebAcl in",
                "interface ISP ip access-group WebAcl out",
                "interface Bridge0 ip access-group WebAcl in",
                "interface Bridge0 ip access-group GuestAcl out",
            ],
        )
        .await?;

        let binding = |interface: &str, list: &str, direction| {
            Binding::new(interface.to_owned(), list.to_owned(), direction)
        };
        for expected in [
            binding("ISP", "WebAcl", Direction::In),
            binding("ISP", "WebAcl", Direction::Out),
            binding("Bridge0", "WebAcl", Direction::In),
            binding("Bridge0", "GuestAcl", Direction::Out),
        ] {
            assert!(firewall.bindings().contains(&expected), "{expected:?}");
        }
        let mut interfaces: Vec<&str> = firewall
            .bindings_of("WebAcl")
            .map(Binding::interface)
            .collect();
        interfaces.sort_unstable();
        assert_eq!(interfaces, ["Bridge0", "ISP", "ISP"]);
        assert!(
            !firewall
                .bindings()
                .contains(&binding("ISP", "GuestAcl", Direction::In))
        );
        fixture.shutdown().await?;
    }
    Ok(())
}
