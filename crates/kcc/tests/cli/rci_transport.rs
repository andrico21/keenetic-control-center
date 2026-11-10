use kcc_testkit::{DEFAULT_PASSWORD, FakeRouter, FaultInjection, model::Profile};
use tokio::runtime::Builder;

use super::support::{Env, TestResult, router};

#[test]
fn rci_get_uses_show_transport_only_for_catalog_show_commands() -> TestResult {
    let runtime = Builder::new_multi_thread().enable_all().build()?;
    let (address, fake) = runtime.block_on(
        FakeRouter::builder(Profile::default())
            .faults(FaultInjection::default().show_requires_post("show/clock/date"))
            .build()?
            .serve(([127, 0, 0, 1], 0).into()),
    )?;
    let env = Env::new("")?;
    let password = env.write("router.password", DEFAULT_PASSWORD)?;
    env.write_config(&router("lab", address, &password))?;

    let before = fake.request_log().len();
    let shown = env.kcc(&["--router", "lab", "rci", "get", "show", "version"])?;
    let post_only = env.kcc(&["--router", "lab", "rci", "get", "show", "clock", "date"])?;
    let setting = env.kcc(&["--router", "lab", "rci", "get", "system", "country"])?;

    assert_eq!(shown.code, 0_i32, "show command: {}", shown.stderr);
    assert_eq!(
        post_only.code, 0_i32,
        "show command the router serves only by POST: {}",
        post_only.stderr
    );
    assert_ne!(
        setting.code, 0_i32,
        "missing setting unexpectedly succeeded"
    );
    let requests = fake
        .request_log()
        .into_iter()
        .skip(before)
        .collect::<Vec<_>>();
    let methods = |path: &str| {
        requests
            .iter()
            .filter(|request| request.path() == path)
            .map(|request| request.method().as_str())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        methods("/rci/show/version"),
        ["GET", "GET", "GET", "GET"],
        "catalog discovery of each run and the requested show all use GET"
    );
    assert_eq!(
        methods("/rci/show/clock/date"),
        ["GET", "POST"],
        "a show the router refuses by GET is read again by POST"
    );
    assert_eq!(
        methods("/rci/system/country"),
        ["GET"],
        "ordinary GET never falls back to POST"
    );
    Ok(())
}
