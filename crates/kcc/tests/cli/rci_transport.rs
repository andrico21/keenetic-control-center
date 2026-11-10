use kcc_testkit::{DEFAULT_PASSWORD, FakeRouter, model::Profile};
use tokio::runtime::Builder;

use super::support::{Env, TestResult, router};

#[test]
fn rci_get_uses_show_transport_only_for_catalog_show_commands() -> TestResult {
    let runtime = Builder::new_multi_thread().enable_all().build()?;
    let (address, fake) = runtime.block_on(
        FakeRouter::builder(Profile::default())
            .build()?
            .serve(([127, 0, 0, 1], 0).into()),
    )?;
    let env = Env::new("")?;
    let password = env.write("router.password", DEFAULT_PASSWORD)?;
    env.write_config(&router("lab", address, &password))?;

    let before = fake.request_log().len();
    let shown = env.kcc(&["--router", "lab", "rci", "get", "show", "version"])?;
    let setting = env.kcc(&["--router", "lab", "rci", "get", "system", "country"])?;

    assert_eq!(shown.code, 0_i32, "show command: {}", shown.stderr);
    assert_ne!(
        setting.code, 0_i32,
        "missing setting unexpectedly succeeded"
    );
    let requests = fake
        .request_log()
        .into_iter()
        .skip(before)
        .collect::<Vec<_>>();
    let show_methods = requests
        .iter()
        .filter(|request| request.path() == "/rci/show/version")
        .map(|request| request.method().as_str())
        .collect::<Vec<_>>();
    let setting_methods = requests
        .iter()
        .filter(|request| request.path() == "/rci/system/country")
        .map(|request| request.method().as_str())
        .collect::<Vec<_>>();
    assert!(
        !show_methods.is_empty(),
        "catalog show reaches its show endpoint"
    );
    assert!(
        show_methods.iter().all(|method| *method == "GET"),
        "catalog show transport never uses POST: {show_methods:?}"
    );
    assert_eq!(
        setting_methods,
        ["GET"],
        "ordinary GET never falls back to POST"
    );
    Ok(())
}
