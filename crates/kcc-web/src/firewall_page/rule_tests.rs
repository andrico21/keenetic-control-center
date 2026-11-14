//! Unit tests of what the page shows of a rule's sides.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#![expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]

use core::error::Error;

use kcc_domain::firewall::rule_words::RuleForm;

use super::{address_text, protocol_label};

/// `line` split into words.
fn words(line: &str) -> Vec<String> {
    line.split_whitespace().map(str::to_owned).collect()
}

#[test]
fn one_host_and_a_network_are_shown_as_people_read_them() -> Result<(), Box<dyn Error>> {
    let documented =
        "permit tcp 192.0.2.10 255.255.255.255 port eq 1024 198.51.100.0 255.255.255.0 port eq 443";
    let rule = RuleForm::read(&words(documented)).ok_or("documented form")?;
    assert_eq!(
        address_text(rule.source()).as_deref(),
        Some("192.0.2.10"),
        "one host"
    );
    assert_eq!(
        address_text(rule.destination()).as_deref(),
        Some("198.51.100.0/24"),
        "a network"
    );
    let earlier = RuleForm::read(&words(
        "deny 0.0.0.0 0.0.0.0 1024 198.51.100.20 255.255.255.255 443",
    ))
    .ok_or("the earlier form")?;
    assert_eq!(protocol_label(earlier.protocol()), None, "no protocol");
    assert_eq!(address_text(earlier.source()), None, "every address");
    Ok(())
}
