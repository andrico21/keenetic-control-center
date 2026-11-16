//! Router-user domain integration coverage.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests use assertions and a boxed error result"
)]

mod support;

use std::fs;

use kcc_app::audit::AUDIT_FILE_NAME;
use kcc_domain::{DomainError, router_users};
use kcc_testkit::DEFAULT_LOGIN;
use secrecy::SecretString;

use crate::support::{Fixture, PROFILES, TestResult, TraceCapture};

#[tokio::test]
async fn create_with_tags_is_visible_through_show_rc_user() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;
        let operation =
            router_users::plan_create(fixture.context(), "operator", &["cli", "readonly"])?;
        let request = router_users::change_request(&operation)?;
        let mut changes = fixture.changes().await?;
        drop(changes.apply_cli(request).await?);
        drop(changes);

        let users = router_users::read_users(fixture.context()).await?;
        let operator = users
            .iter()
            .find(|user| user.name.as_deref() == Some("operator"))
            .ok_or("created operator missing")?;
        assert_eq!(operator.tags, ["cli", "readonly"]);
        fixture.shutdown().await?;
    }
    Ok(())
}

#[tokio::test]
async fn protected_account_refusals_send_no_router_request() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;
        let before = fixture.handle().request_count();
        let own = router_users::protection::OwnLogins::new(DEFAULT_LOGIN, None)?;

        assert!(matches!(
            router_users::plan_tag(fixture.context(), "admin", &own, ("cli", false)),
            Err(DomainError::ProtectedAccount)
        ));
        assert!(matches!(
            router_users::plan_delete(fixture.context(), DEFAULT_LOGIN, &own),
            Err(DomainError::ProtectedAccount)
        ));
        assert!(matches!(
            router_users::plan_password(
                fixture.context(),
                DEFAULT_LOGIN,
                &own,
                SecretString::from("replacement"),
            ),
            Err(DomainError::ProtectedAccount)
        ));
        assert_eq!(fixture.handle().request_count(), before);
        fixture.shutdown().await?;
    }
    Ok(())
}

/// W1-07, W4-03, C-24: both logins kcc signs in with are protected.
///
/// The primary and the read-only login keep their password, their tags and the account
/// itself; a profile that names no login protects every account; nothing is sent.
#[tokio::test]
async fn own_logins_are_refused_and_a_missing_login_protects_every_account() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;
        let router = fixture.context();
        let before = fixture.handle().request_count();
        let own = router_users::protection::OwnLogins::new(DEFAULT_LOGIN, Some("monitor"))?;

        for name in [DEFAULT_LOGIN, "monitor"] {
            let secret = SecretString::from(format!("replacement-{}", 7_u8));
            assert!(matches!(
                router_users::plan_password(router, name, &own, secret),
                Err(DomainError::ProtectedAccount)
            ));
            assert!(matches!(
                router_users::plan_delete(router, name, &own),
                Err(DomainError::ProtectedAccount)
            ));
            assert!(matches!(
                router_users::plan_tag(router, name, &own, ("http", false)),
                Err(DomainError::ProtectedAccount)
            ));
            drop(router_users::plan_tag(router, name, &own, ("http", true))?);
        }
        drop(router_users::plan_tag(
            router,
            "operator",
            &own,
            ("http", false),
        )?);
        drop(router_users::plan_delete(router, "operator", &own)?);
        for (login, reader) in [("", None), (DEFAULT_LOGIN, Some(""))] {
            assert!(matches!(
                router_users::protection::OwnLogins::new(login, reader),
                Err(DomainError::ProtectedAccount)
            ));
        }
        assert_eq!(fixture.handle().request_count(), before);
        fixture.shutdown().await?;
    }
    Ok(())
}

#[tokio::test]
async fn password_write_hashes_and_never_exposes_plaintext() -> TestResult {
    for firmware in PROFILES {
        let trace = TraceCapture::install();
        let fixture = Fixture::spawn(firmware).await?;
        let secret = "\u{43f}\u{430}\u{440}\u{43e}\u{43b}\u{44c} with spaces \"quotes\"";
        // Not the fixture's own login: the fake router (like a real one) ends the sessions of an
        // account whose password changes, which would make the fixture's follow-up reads fail.
        let operation = router_users::plan_password(
            fixture.context(),
            "operator",
            &router_users::protection::OwnLogins::new(DEFAULT_LOGIN, None)?,
            SecretString::from(secret.to_owned()),
        )?;
        assert!(!format!("{operation:?}").contains(secret));
        assert!(!serde_json::to_string(&operation.requests)?.contains(secret));
        let request = router_users::change_request(&operation)?;
        assert!(!format!("{request:?}").contains(secret));
        assert!(!serde_json::to_string(&request)?.contains(secret));
        let mut changes = fixture.changes().await?;

        let result = changes.apply_cli(request).await?;
        let users = router_users::read_users(fixture.context()).await?;

        assert!(!format!("{result:?}").contains(secret));
        assert!(!serde_json::to_string(&result)?.contains(secret));
        assert!(!format!("{users:?}").contains(secret));
        assert!(!serde_json::to_string(&users)?.contains(secret));
        assert!(
            fixture
                .handle()
                .running_config_text()
                .contains("password md5")
        );
        assert!(!fixture.handle().running_config_text().contains(secret));
        assert!(!format!("{:?}", fixture.handle().request_log()).contains(secret));
        let audit = fs::read(fixture.state_dir().join(AUDIT_FILE_NAME))?;
        assert!(!String::from_utf8(audit)?.contains(secret));
        assert!(!trace.text()?.contains(secret));
        drop(changes);
        fixture.shutdown().await?;
    }
    Ok(())
}

#[tokio::test]
async fn password_control_character_is_refused_before_router_request() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;
        let before = fixture.handle().request_count();

        let result = router_users::plan_password(
            fixture.context(),
            DEFAULT_LOGIN,
            &router_users::protection::OwnLogins::new("operator", None)?,
            SecretString::from("bad\npassword".to_owned()),
        );

        assert!(matches!(result, Err(DomainError::Validation { issues: _ })));
        assert_eq!(fixture.handle().request_count(), before);
        fixture.shutdown().await?;
    }
    Ok(())
}
