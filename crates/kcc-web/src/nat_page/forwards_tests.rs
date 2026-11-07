//! Unit tests of the port forwarding rule parser: the forms the router stores, and the
//! ones the NAT domain cannot change.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#![expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]

use core::error::Error;

use kcc_domain::nat::model::{ConfiguredRule, ForwardTarget};
use serde_json::json;

use super::Forward;

/// The rule of a configured line's words.
fn rule(words: &[&str]) -> Result<Option<Forward>, Box<dyn Error>> {
    let configured: ConfiguredRule = serde_json::from_value(json!({ "command": words }))?;
    Ok(Forward::from_rule(&configured))
}

#[test]
fn stored_forms_parse_into_domain_rules() -> Result<(), Box<dyn Error>> {
    let single = rule(&["tcp", "ISP", "8443", "192.0.2.44", "443"])?.ok_or("single port")?;
    let domain = single.domain_rule().ok_or("a domain rule")?;
    assert_eq!(domain.port, Some(8443), "port");
    assert_eq!(domain.to_port, Some(443), "target port");
    assert_eq!(
        domain.target,
        ForwardTarget::Address("192.0.2.44".to_owned()),
        "target"
    );
    let range = rule(&["udp", "ISP", "5000", "through", "5010", "192.0.2.45"])?.ok_or("range")?;
    assert_eq!(range.ports(), Some((5000, Some(5010))), "range");
    let host = rule(&["ISP", "02:00:00:00:10:01"])?.ok_or("whole host")?;
    assert_eq!(host.ports(), None, "every port");
    assert!(
        matches!(
            host.domain_rule().map(|found| found.target),
            Some(ForwardTarget::Host(_))
        ),
        "a MAC address is a registered host"
    );
    Ok(())
}

#[test]
fn forms_the_domain_cannot_express_are_listed_only() -> Result<(), Box<dyn Error>> {
    let network = rule(&["tcp", "203.0.113.0", "255.255.255.0", "80", "192.0.2.44"])?
        .ok_or("address and mask")?;
    assert_eq!(
        network.incoming(),
        "203.0.113.0 255.255.255.0",
        "incoming network"
    );
    assert!(network.domain_rule().is_none(), "no interface to name");
    let to_interface = rule(&["tcp", "ISP", "80", "Wireguard0"])?.ok_or("to an interface")?;
    assert!(to_interface.domain_rule().is_none(), "interface target");
    assert!(
        rule(&["tcp", "ISP", "80", "192.0.2.44", "443", "extra"])?.is_none(),
        "an unknown tail"
    );
    Ok(())
}
