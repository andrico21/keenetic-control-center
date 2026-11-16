//! Every path method of the credential store checks the router id first.

use std::path::Path;

use kcc_app::credentials::{
    CredentialError, CredentialKind, CredentialStore, rollback::SealedRecords,
};
use secrecy::SecretString;

use super::{Fixture, TestResult};

/// A credential store entry point applied to one router id; the answer is dropped.
type PathMethod = fn(&CredentialStore, &str) -> Result<(), CredentialError>;

/// SEC2-15: every path method of the credential store refuses an invalid router id.
///
/// The id is refused before it builds a path, a lock or associated data, so an id
/// holding the binding separator never reaches the record of another router or kind.
#[test]
fn every_path_method_refuses_an_invalid_router_id() -> TestResult {
    let methods: [(&str, PathMethod); 10] = [
        ("store", |store, router| {
            store.store(
                router,
                CredentialKind::Password,
                &SecretString::from("fixture-password"),
            )
        }),
        ("open", |store, router| {
            store
                .open(router, CredentialKind::Password)
                .map(|_secret| ())
        }),
        ("exists", |store, router| {
            store
                .exists(router, CredentialKind::Password)
                .map(|_found| ())
        }),
        ("remove", CredentialStore::remove),
        ("remove_kind", |store, router| {
            store.remove_kind(router, CredentialKind::Token)
        }),
        ("migrate", |store, router| {
            store.migrate(router).map(|_state| ())
        }),
        ("manages", |store, router| {
            store
                .manages(router, CredentialKind::Password, Path::new("a.sealed"))
                .map(|_managed| ())
        }),
        ("sealed_path", |store, router| {
            store
                .sealed_path(router, CredentialKind::Password)
                .map(|_path| ())
        }),
        ("legacy_path", |store, router| {
            store.legacy_path(router).map(|_path| ())
        }),
        ("SealedRecords::take", |store, router| {
            SealedRecords::take(store, router).map(|_records| ())
        }),
    ];
    let fixture = Fixture::new()?;
    for kind in CredentialKind::ALL {
        fixture
            .credentials
            .store("a", kind, &SecretString::from("fixture-secret"))?;
    }
    let long = "a".repeat(33);
    let invalid = [
        "",
        "Home",
        "../a",
        "a/b",
        "a.b",
        "a:token",
        "a:read",
        long.as_str(),
    ];

    for router in invalid {
        for (name, method) in methods {
            assert!(
                matches!(
                    method(&fixture.credentials, router),
                    Err(CredentialError::Record)
                ),
                "{name} {router:?}"
            );
        }
    }
    Ok(())
}
