//! NAT domain integration coverage.

#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests use assertions and a boxed error result"
)]

mod support;

use kcc_domain::nat::{
    change,
    model::{PortForward, Protocol},
    read,
};

use crate::support::{Fixture, TestResult};

#[tokio::test]
async fn port_forward_addition_is_verified_by_fresh_running_configuration() -> TestResult {
    let fixture = Fixture::spawn().await?;
    let rule = PortForward::to_address(Protocol::Tcp, "ISP", 8443, "192.0.2.44").with_to_port(443);
    let mut changes = fixture.changes().await?;

    drop(
        change::apply(
            &mut changes,
            fixture.context(),
            &change::plan_add_forward(fixture.context(), &rule)?,
        )
        .await?,
    );

    assert!(
        read::running_forwards(fixture.context())
            .await?
            .iter()
            .any(|row| {
                row.command == ["tcp", "ISP", "8443", "192.0.2.44", "443"].map(str::to_owned)
            })
    );
    drop(changes);
    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn nat_interface_add_and_remove_are_verified_by_fresh_reads() -> TestResult {
    let fixture = Fixture::spawn().await?;
    let mut changes = fixture.changes().await?;

    drop(
        change::apply(
            &mut changes,
            fixture.context(),
            &change::plan_add_interface(fixture.context(), "Bridge0")?,
        )
        .await?,
    );
    assert!(
        read::interfaces(fixture.context())
            .await?
            .iter()
            .any(|row| row.interface.as_deref() == Some("Bridge0"))
    );

    drop(
        change::apply(
            &mut changes,
            fixture.context(),
            &change::plan_remove_interface(fixture.context(), "Bridge0")?,
        )
        .await?,
    );
    assert!(
        !read::interfaces(fixture.context())
            .await?
            .iter()
            .any(|row| row.interface.as_deref() == Some("Bridge0"))
    );
    drop(changes);
    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn runtime_nat_pages_never_exceed_two_hundred_rows() -> TestResult {
    let fixture = Fixture::spawn().await?;

    let first = read::sessions_page(fixture.context(), 0).await?;
    let second = read::sessions_page(fixture.context(), read::PAGE_SIZE).await?;
    let third = read::sessions_page(fixture.context(), read::PAGE_SIZE * 2).await?;

    assert_eq!(first.rows.len(), 200);
    assert_eq!(second.rows.len(), 200);
    assert_eq!(third.rows.len(), 80);
    let pages = fixture
        .handle()
        .request_log()
        .into_iter()
        .filter(|request| request.path() == "/rci/show/ip/nat")
        .collect::<Vec<_>>();
    assert_eq!(pages.len(), 3);
    assert!(pages.iter().all(|request| {
        request
            .query()
            .iter()
            .any(|pair| pair == &("limit".to_owned(), "200".to_owned()))
    }));
    fixture.shutdown().await?;
    Ok(())
}
