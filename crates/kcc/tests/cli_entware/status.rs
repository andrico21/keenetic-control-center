//! `kcc entware status`: one read document for any role that may read.

use kcc_app::{
    permissions::{Permission, Role, RolesDocument},
    persist::StateStore,
};
use kcc_i18n::keys;
use serde_json::Value;

use super::{
    lab::{DRIVE, Lab, en},
    support::TestResult,
};

/// Todo 13: a viewer reads the status as one JSON document with the read model's field
/// names, and nothing is written.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn status_is_one_document_with_the_read_model_fields() -> TestResult {
    let lab = Lab::spawn("viewer").await?;

    let status = lab.json(&["entware", "status"])?;

    let object = status.as_object().ok_or("not an object")?;
    let mut fields = object.keys().map(String::as_str).collect::<Vec<_>>();
    fields.sort_unstable();
    assert_eq!(
        fields,
        [
            "arch",
            "dns_filter_uses_opkg",
            "drives",
            "ext_component",
            "initializable",
            "opkg_component",
            "possible",
            "settings"
        ],
        "{status}"
    );
    assert_eq!(
        status.pointer("/drives/0/disk_arg"),
        Some(&Value::from(DRIVE)),
        "{status}"
    );
    assert_eq!(
        status.get("arch"),
        Some(&Value::from("aarch64")),
        "{status}"
    );
    assert_eq!(lab.commands(), Vec::<String>::new());
    lab.shutdown().await
}

/// Todo 13: a CLI role without `Read` is refused the status with exit 10 before any router
/// request; the same role with `Read` reads it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn status_needs_read() -> TestResult {
    for (permissions, code) in [(&[][..], 10_i32), (&[Permission::Read][..], 0_i32)] {
        let lab = Lab::spawn("custom").await?;
        let mut roles = RolesDocument::default();
        roles.roles.push(Role::new(
            "custom".to_owned(),
            permissions.iter().copied(),
            vec!["*".to_owned()],
        ));
        StateStore::open(&lab.env.state_dir())?.write(&roles)?;

        let run = lab.run(&["entware", "status"])?;

        assert_eq!(run.code, code, "{permissions:?}: {run:?}");
        if code == 10_i32 {
            assert!(
                run.stderr.contains(&en(keys::CLI_ERROR_POLICY, &[])),
                "{run:?}"
            );
            assert_eq!(lab.fake.request_count(), 0, "{run:?}");
        }
        lab.shutdown().await?;
    }
    Ok(())
}
