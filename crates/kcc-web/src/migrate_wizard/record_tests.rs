//! The record's step transitions.
#![expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
use super::Record;
use crate::{
    migrate_wizard::kinds::{Source, Step},
    wizard::flow::Flow as _,
};

#[test]
fn going_back_stops_at_the_preview_and_a_restore_source() {
    let mut record = Record::new(
        "1700000000-0001020304050607".to_owned(),
        "admin".to_owned(),
        1,
    );
    record.choose_source(Source::File {
        name: "startup.txt".to_owned(),
    });
    record.choose_target("ultra".to_owned(), None);
    record.confirm_target(false);
    assert_eq!(record.step(), Step::Mapping, "on to the maps");
    assert!(record.go_back(Step::Source), "the source can change");
    assert!(!record.go_back(Step::Mapping), "never forward");
    let mut restore = Record::restore(
        "1700000000-0001020304050607".to_owned(),
        "admin".to_owned(),
        1,
        ("ultra".to_owned(), "1-manual.txt".to_owned()),
    );
    restore.confirm_target(false);
    assert!(
        !restore.go_back(Step::Source),
        "a restore's source is fixed"
    );
    assert!(
        restore.go_back(Step::Target),
        "its target warnings show again"
    );
}
