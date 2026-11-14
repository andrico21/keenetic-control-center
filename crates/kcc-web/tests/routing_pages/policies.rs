//! Connection policies: added, edited and deleted through the page, each read back.
//!
//! A policy is added with its description, an interface is permitted at an order and
//! multipath turned on; an interface is taken off and a policy deleted once its name is
//! typed; a name and a description are refused before anything is sent.

use axum::http::StatusCode;
use kcc_i18n::keys;

use crate::{
    get, post,
    support::{
        outcome::TestResult,
        page::en,
        typed_name::{Ask, TypedName, typed_names},
        web::{Fixture, ROUTER},
    },
};

#[tokio::test]
async fn a_policy_is_added_with_an_interface_in_order_and_multipath() -> TestResult {
    let fixture = Fixture::new().await?;
    let admin = fixture.login("admin").await?;
    let path = "/ui/r/home/routing/policies";
    let page = get(&fixture, &admin, path, StatusCode::OK).await?;
    assert!(page.contains("Policy0"), "the router's policy: {page}");
    let new = "/ui/r/home/routing/policy/new";
    let fields = [("name", "Policy9"), ("description", "uplink")];
    let created = post(&fixture, &admin, (new, &fields), StatusCode::OK).await?;
    assert!(
        created.contains(&en(keys::WEB_KIT_DONE_UNSAVED)),
        "{created}"
    );
    assert!(
        created.contains("Policy9") && created.contains("uplink"),
        "read back"
    );
    let permit = "/ui/r/home/routing/policy/permit?name=Policy9";
    let order = [("interface", "ISP"), ("order", "3")];
    let permitted = post(&fixture, &admin, (permit, &order), StatusCode::OK).await?;
    assert!(permitted.contains("ISP, order 3"), "in order: {permitted}");
    let multipath = "/ui/r/home/routing/policy/multipath?name=Policy9&value=on";
    let on = post(&fixture, &admin, (multipath, &[]), StatusCode::OK).await?;
    assert!(
        on.contains(&en(keys::WEB_ROUTING_MULTIPATH_OFF)),
        "now offers Off"
    );
    let running = fixture.handle().running_config_text();
    for line in [
        "ip policy Policy9",
        "description uplink",
        "permit global ISP order 3",
        "multipath",
    ] {
        assert!(running.contains(line), "{line} in {running}");
    }
    Ok(())
}

#[tokio::test]
async fn an_interface_is_taken_off_and_a_policy_deleted_once_its_name_is_typed() -> TestResult {
    let fixture = Fixture::new().await?;
    let client = fixture.registry().client(ROUTER).await?;
    for line in [
        "ip policy Policy9",
        "ip policy Policy9 permit global ISP order 3",
    ] {
        drop(client.parse(line).await?);
    }
    let admin = fixture.login("admin").await?;
    let unpermit = "/ui/r/home/routing/policy/unpermit?name=Policy9&interface=ISP";
    drop(post(&fixture, &admin, (unpermit, &[]), StatusCode::OK).await?);
    let running = fixture.handle().running_config_text();
    assert!(
        !running.contains("permit global ISP"),
        "taken off: {running}"
    );
    let delete = "/ui/r/home/routing/policy/delete";
    drop(
        typed_names(
            &fixture,
            &[TypedName {
                action: "web.routing_policy_delete",
                account: "admin",
                denied: None,
                ask: Ask::Get(&format!("{delete}?name=Policy9")),
                title: None,
                post: delete,
                fields: &[("object", "Policy9")],
                names: ("Policy8", "Policy9"),
                ran: ("success", keys::WEB_KIT_DONE_UNSAVED),
                rereads: true,
            }],
        )
        .await?,
    );
    let after = fixture.handle().running_config_text();
    assert!(!after.contains("ip policy Policy9"), "deleted: {after}");
    Ok(())
}

#[tokio::test]
async fn a_policy_name_with_a_space_is_refused_before_anything_is_sent() -> TestResult {
    let fixture = Fixture::new().await?;
    let admin = fixture.login("admin").await?;
    let before = fixture.handle().running_config_text();
    let new = "/ui/r/home/routing/policy/new";
    let spaced = [("name", "bad name")];
    let refused = post(
        &fixture,
        &admin,
        (new, &spaced),
        StatusCode::UNPROCESSABLE_ENTITY,
    )
    .await?;
    assert!(
        refused.contains(&en(keys::WEB_ROUTING_ERROR_NAME)),
        "{refused}"
    );
    let words = [("name", "Policy7"), ("description", "two words")];
    let word = post(
        &fixture,
        &admin,
        (new, &words),
        StatusCode::UNPROCESSABLE_ENTITY,
    )
    .await?;
    assert!(word.contains(&en(keys::WEB_ROUTING_ERROR_WORD)), "{word}");
    assert_eq!(
        fixture.handle().running_config_text(),
        before,
        "nothing changed"
    );
    Ok(())
}
