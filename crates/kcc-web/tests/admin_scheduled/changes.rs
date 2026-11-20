//! Adding, editing, pausing, resuming and deleting schedules, and what the scheduler and
//! the store refuse.

extern crate alloc;

use alloc::sync::Arc;

use axum::http::StatusCode;
use kcc_app::schedules::model::{
    Action, Owner,
    names::{ClientMac, PolicyName},
};
use kcc_i18n::keys;
use kcc_web::admin_scheduled::{ScheduleDraft, ScheduleRefusal};
use serde_json::json;

use crate::{
    fixture::{PAGE, Scheduled},
    stub::{Asked, Stub},
    support::{
        outcome::TestResult,
        page::{en, text},
    },
};

/// The fixture's registered client.
const CLIENT: &str = "02:00:00:00:10:01";

/// The form of a policy switch of the fixture's registered client to `policy`.
fn policy_form(policy: &str) -> Vec<(&str, &str)> {
    vec![
        ("name", "Kids offline"),
        ("router", "home"),
        ("days", "mon"),
        ("days", "fri"),
        ("hour", "21"),
        ("minute", "30"),
        ("zone", "Europe/Berlin"),
        ("kind", "policy_switch"),
        ("mac", CLIENT),
        ("policy", policy),
    ]
}

/// The form of a restart of `home`, its router name typed as `typed`.
pub(crate) fn reboot_form(typed: &str) -> Vec<(&str, &str)> {
    vec![
        ("name", "Weekly restart"),
        ("router", "home"),
        ("days", "sun"),
        ("hour", "4"),
        ("minute", "0"),
        ("zone", "UTC"),
        ("kind", "reboot"),
        ("confirm_name", typed),
    ]
}

/// Regression (todo 15): a policy schedule is stored with the clicker as owner.
///
/// The dialog offers the router's registered client and its policies; the schedule is
/// stored once the scheduler's check passed, and audited by id, action kind and router
/// only.
#[tokio::test]
async fn a_policy_schedule_is_stored_with_the_clicker_as_owner() -> TestResult {
    let stub = Stub::new();
    let fixture = Scheduled::build(Some(Arc::clone(&stub))).await?;
    let admin = fixture.login("admin").await?;
    let dialog = fixture
        .html(
            "/ui/admin/scheduled/new?router=home&kind=policy_switch",
            &admin,
        )
        .await?;
    assert!(
        dialog.contains(&format!(
            "<option value=\"{CLIENT}\">wired-registered ({CLIENT})"
        )),
        "the registered client: {dialog}"
    );
    assert!(
        !dialog.contains("02:00:00:00:10:02"),
        "no unregistered client"
    );
    assert!(dialog.contains("<option value=\"Policy0\">"), "the policy");
    let created = fixture.post(PAGE, &admin, &policy_form("Policy0")).await?;
    assert_eq!(created.status(), StatusCode::OK, "created");
    assert!(
        text(created)
            .await?
            .contains(&en(keys::WEB_ADMIN_SCHEDULED_CREATED)),
        "the toast"
    );
    let stored = fixture.schedules()?;
    let [schedule] = stored.as_slice() else {
        return Err(format!("one schedule: {stored:?}").into());
    };
    let action = Action::PolicySwitch {
        mac: ClientMac::parse(CLIENT)?,
        policy: PolicyName::parse("Policy0")?,
    };
    assert_eq!(schedule.action, action, "the action");
    assert_eq!(
        schedule.owner,
        Owner::Web {
            username: "admin".to_owned()
        },
        "the clicker owns it"
    );
    assert_eq!(
        stub.asked(),
        vec![Asked::Check(
            "admin".to_owned(),
            ScheduleDraft::new("home".to_owned(), action)
        )],
        "checked once as the clicker"
    );
    let audited = fixture.audited("web.schedule_create").await?;
    let [entry] = audited.as_slice() else {
        return Err(format!("one audit entry: {audited:?}").into());
    };
    assert_eq!(entry.outcome, "success", "outcome");
    assert_eq!(
        entry.params_redacted,
        json!({ "schedule": schedule.id, "action": "policy_switch", "router": "home" }),
        "no client and no policy in the audit log"
    );
    Ok(())
}

/// Regression (todo 15): an edit the scheduler refuses (a policy the router lacks) shows
/// its message in the dialog, changes nothing and is audited with the refusal's code.
#[tokio::test]
async fn an_edit_to_an_unknown_policy_is_refused_and_changes_nothing() -> TestResult {
    let stub = Stub::new();
    let fixture = Scheduled::build(Some(Arc::clone(&stub))).await?;
    let admin = fixture.login("admin").await?;
    let created = fixture.post(PAGE, &admin, &policy_form("Policy0")).await?;
    assert_eq!(created.status(), StatusCode::OK, "created");
    let before = fixture.schedules()?;
    let id = before
        .first()
        .map(|schedule| schedule.id.clone())
        .ok_or("stored")?;
    stub.refuse_checks(ScheduleRefusal::PolicyUnknown);
    let mut edit = policy_form("Nope");
    edit.push(("id", &id));
    let refused = fixture
        .post("/ui/admin/scheduled/edit", &admin, &edit)
        .await?;
    assert_eq!(
        refused.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "refused"
    );
    assert!(
        text(refused)
            .await?
            .contains(&en(keys::WEB_SCHEDULED_REFUSED_POLICY_UNKNOWN)),
        "the refusal's message"
    );
    assert_eq!(fixture.schedules()?, before, "nothing changed");
    let outcomes: Vec<String> = fixture
        .audited("web.schedule_update")
        .await?
        .into_iter()
        .map(|entry| entry.outcome)
        .collect();
    assert_eq!(outcomes, ["policy_unknown"], "audited as refused");
    Ok(())
}

/// Regression (todo 15): a restart schedule needs the router's name typed.
#[tokio::test]
async fn a_reboot_schedule_needs_the_typed_router_name() -> TestResult {
    let fixture = Scheduled::build(Some(Stub::new())).await?;
    let admin = fixture.login("admin").await?;
    for typed in ["", "other"] {
        let refused = fixture.post(PAGE, &admin, &reboot_form(typed)).await?;
        assert_eq!(
            refused.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "typed {typed:?}"
        );
        assert!(
            text(refused)
                .await?
                .contains(&en(keys::WEB_ADMIN_SCHEDULED_ERROR_CONFIRM)),
            "the mismatch is shown"
        );
    }
    assert!(
        fixture.schedules()?.is_empty(),
        "nothing stored unconfirmed"
    );
    let created = fixture.post(PAGE, &admin, &reboot_form("home")).await?;
    assert_eq!(created.status(), StatusCode::OK, "confirmed");
    assert_eq!(fixture.schedules()?.len(), 1, "stored");
    Ok(())
}

/// Regression (todo 15): a role with `ManageSchedules` but without `Destructive` cannot
/// add a restart schedule: the store refuses it even though the scheduler's check passed.
#[tokio::test]
async fn a_role_without_destructive_cannot_schedule_a_reboot() -> TestResult {
    let fixture = Scheduled::build(Some(Stub::new())).await?;
    let sam = fixture.login("sam").await?;
    let refused = fixture.post(PAGE, &sam, &reboot_form("home")).await?;
    assert_eq!(
        refused.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "refused"
    );
    assert!(
        text(refused)
            .await?
            .contains(&en(keys::WEB_SCHEDULED_REFUSED_FORBIDDEN)),
        "the refusal is shown"
    );
    assert!(fixture.schedules()?.is_empty(), "nothing stored");
    let outcomes: Vec<String> = fixture
        .audited("web.schedule_create")
        .await?
        .into_iter()
        .map(|entry| entry.outcome)
        .collect();
    assert_eq!(outcomes, ["forbidden"], "audited as forbidden");
    Ok(())
}
