//! The router removal's confirmation names an Active Entware SSH enrolment: kcc's key line
//! stays authorized on the router after the profile is gone.

use kcc_app::{
    entware_ssh::state::{EnrolmentState, SshEnrolment, SshStore},
    persist::StateStore,
};
use kcc_i18n::keys;

use crate::support::{
    build::master_key,
    outcome::TestResult,
    page::{en, text},
    web::{Fixture, ROUTER},
};

/// The removal dialog of the router as the administrator sees it.
async fn dialog(fixture: &Fixture) -> TestResult<String> {
    let admin = fixture.login("admin").await?;
    text(
        fixture
            .get(&format!("/ui/routers/{ROUTER}/delete"), &admin)
            .await?,
    )
    .await
}

/// Todo 15: the removal dialog says the router still authorizes kcc's key line when the
/// enrolment is Active, and says nothing without one or while it is Pending.
#[tokio::test]
async fn the_removal_dialog_names_an_active_enrolment() -> TestResult {
    let fixture = Fixture::new().await?;
    let notice = "id=\"router-delete-ssh-notice\"";
    let plain = dialog(&fixture).await?;
    assert!(plain.contains(&en(keys::WEB_ROUTER_DELETE_TEXT)), "{plain}");
    assert!(!plain.contains(notice), "{plain}");
    let store = SshStore::new(StateStore::open(&fixture.state_dir())?, master_key());
    let mut record = SshEnrolment::default();
    store.save(ROUTER, &record)?;
    assert!(!dialog(&fixture).await?.contains(notice), "pending");
    record.state = EnrolmentState::Active;
    store.save(ROUTER, &record)?;
    let active = dialog(&fixture).await?;
    assert!(active.contains(notice), "{active}");
    assert!(
        active.contains(&en(keys::WEB_SYSTEM_ENTWARE_SSH_DELETE_NOTICE)),
        "{active}"
    );
    Ok(())
}
