//! Unit tests of the stored-rule reader: the documented and kcc's earlier forms, and the
//! forms that keep only their stored words.
#![expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]

use super::{RuleForm, StoredRule};

/// `line` split into words.
fn words(line: &str) -> Vec<String> {
    line.split_whitespace().map(str::to_owned).collect()
}

#[test]
fn documented_and_earlier_forms_are_read() {
    let documented =
        "permit tcp 192.0.2.10 255.255.255.255 port eq 1024 198.51.100.0 255.255.255.0 port eq 443";
    let rule = RuleForm::read(&words(documented));
    assert_eq!(
        rule.as_ref()
            .map(|found| found.words().join(" "))
            .as_deref(),
        Some(documented),
        "written back unchanged"
    );
    assert_eq!(
        rule.as_ref().and_then(|found| found.destination().port()),
        Some(443),
        "port"
    );
    let earlier = RuleForm::read(&words(
        "deny 192.0.2.10 255.255.255.255 1024 198.51.100.20 255.255.255.255 443",
    ));
    assert_eq!(
        earlier.as_ref().map(RuleForm::protocol),
        Some(None),
        "no protocol"
    );
    assert_eq!(
        earlier.as_ref().and_then(|found| found.source().port()),
        Some(1024),
        "bare source port"
    );
    assert_eq!(
        earlier.map(|found| found.rule().destination_port),
        Some(Some(443)),
        "planner rule port"
    );
}

#[test]
fn other_forms_keep_only_their_words() {
    for line in [
        "permit tcp 192.0.2.10 255.255.255.255 port range 1000 2000 198.51.100.20 255.255.255.255",
        "permit tcp 192.0.2.10 255.255.255.255 port lt 1024 198.51.100.20 255.255.255.255",
        "rule 0 description web",
        "permit tcp 192.0.2.10",
    ] {
        assert!(StoredRule::new(words(line)).form().is_none(), "{line}");
    }
}
