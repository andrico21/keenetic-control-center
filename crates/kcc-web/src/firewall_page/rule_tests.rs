//! Unit tests of the firewall rule reader: the documented and the domain's forms, and the
//! forms the page leaves to the command explorer.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#![expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]

use core::error::Error;

use super::{Parsed, StoredRule};

/// `line` split into words.
fn words(line: &str) -> Vec<String> {
    line.split_whitespace().map(str::to_owned).collect()
}

#[test]
fn documented_and_domain_forms_are_read() -> Result<(), Box<dyn Error>> {
    let documented =
        "permit tcp 192.0.2.10 255.255.255.255 port eq 1024 198.51.100.0 255.255.255.0 port eq 443";
    let rule = Parsed::read(&words(documented)).ok_or("documented form")?;
    assert_eq!(rule.words().join(" "), documented, "written back unchanged");
    assert_eq!(
        rule.source().address_text().as_deref(),
        Some("192.0.2.10"),
        "one host"
    );
    assert_eq!(
        rule.destination().address_text().as_deref(),
        Some("198.51.100.0/24"),
        "a network"
    );
    assert_eq!(rule.destination().port(), Some(443), "port");
    let domain = Parsed::read(&words(
        "deny 192.0.2.10 255.255.255.255 1024 198.51.100.20 255.255.255.255 443",
    ))
    .ok_or("the domain's own form")?;
    assert_eq!(domain.protocol_label(), None, "no protocol");
    assert_eq!(domain.source().port(), Some(1024), "bare source port");
    let rule_domain = domain.domain();
    assert_eq!(rule_domain.destination_port, Some(443), "domain rule port");
    Ok(())
}

#[test]
fn other_forms_stay_with_the_command_explorer() {
    for line in [
        "permit tcp 192.0.2.10 255.255.255.255 port range 1000 2000 198.51.100.20 255.255.255.255",
        "permit tcp 192.0.2.10 255.255.255.255 port lt 1024 198.51.100.20 255.255.255.255",
        "rule 0 description web",
        "permit tcp 192.0.2.10",
    ] {
        assert!(StoredRule::new(words(line)).parsed().is_none(), "{line}");
    }
}
