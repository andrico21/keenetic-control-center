//! A labelled router's SSH confirmation names the router and asks for its id.

use kcc_i18n::keys;
use kcc_testkit::entware_ssh::Config;

use super::rig::{CONFIRMED, Rig, hidden};
use crate::support::{
    outcome::TestResult,
    page::{en_with, form, text},
    web::ROUTER,
};

/// A synthetic display name.
const LABEL: &str = "Home Office";

/// Todo 11: the SSH confirmation of a labelled router names it by its name and asks for
/// its id: the name typed back is refused before the router or the SSH server hears
/// anything, the id passes the gate.
// NOT cancel-safe: the rig owns the fakes and the Web UI.
#[tokio::test]
async fn the_ssh_confirmation_names_the_router_and_asks_for_its_id() -> TestResult {
    let rig = Rig::start(Config::default()).await?;
    rig.fixture().label(ROUTER, LABEL).await?;
    let probe = |pairs: &[(&str, &str)]| {
        let mut all = vec![("mode", "bootstrap")];
        all.extend_from_slice(pairs);
        form(&all)
    };
    let seen = || (rig.counters(), rig.fixture().handle().request_count());
    let before = seen();
    let path = "/ui/r/home/system/entware/ssh/probe";
    let asked = text(rig.fixture().post(path, rig.admin(), &probe(&[])).await?).await?;
    let key = keys::WEB_SYSTEM_ENTWARE_SSH_CONFIRM_PROBE;
    let expected = en_with(key, &[("router", LABEL), ("id", ROUTER)]);
    assert_ne!(
        expected,
        en_with(key, &[("router", LABEL), ("id", LABEL)]),
        "the text names the id to type"
    );
    for shown in [
        en_with(
            keys::WEB_SYSTEM_ENTWARE_SSH_CONFIRM_TITLE,
            &[("router", LABEL)],
        ),
        expected,
    ] {
        assert!(asked.contains(&shown), "the dialog misses {shown}: {asked}");
    }
    let by_name = probe(&[("confirm", "yes"), ("confirm_name", LABEL)]);
    let refused = text(rig.fixture().post(path, rig.admin(), &by_name).await?).await?;
    assert!(
        refused.contains(&en_with(
            keys::WEB_EXPLORER_CONFIRM_NAME_ERROR,
            &[("router", ROUTER)]
        )),
        "the name is not the id: {refused}"
    );
    assert_eq!(seen(), before, "nothing reached for the name");
    let by_id = text(
        rig.fixture()
            .post(path, rig.admin(), &probe(&CONFIRMED))
            .await?,
    )
    .await?;
    assert!(
        hidden(&by_id, "nonce").is_some(),
        "the id passes the gate: {by_id}"
    );
    Ok(())
}
