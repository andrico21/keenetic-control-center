//! Grammar refusals before any connection, package operations and `rc.func` semantics.

use kcc_ssh::{
    command::EntwareCommand,
    error::{Grammar, SshError},
    grammar::{PackageName, ServiceAction, ServiceName},
    parse::{self, ActionResult, ServiceState},
    pool::SshPool,
    session::Session,
};
use tokio::time::timeout;

use crate::support::{Fake, LIMIT, TestResult, config, timeouts};

/// Builds `name` as a package and installs it the way a caller would: parse, connect, run.
// NOT cancel-safe: a dropped install leaves its outcome on the fake unknown.
async fn install(fake: &Fake, pool: &SshPool, name: &str) -> Result<u32, SshError> {
    let package = PackageName::parse(name)?;
    let session = fake
        .session(pool, timeouts())
        .await
        .map_err(|_setup| SshError::Connect)?;
    Ok(session
        .run(&EntwareCommand::Install(package))
        .await?
        .exit_status())
}

/// Todo 7: package names carrying an option or shell syntax are refused before any
/// connection is opened.
#[tokio::test]
async fn bad_package_names_are_refused_before_connecting() -> TestResult {
    let fake = Fake::spawn(config()).await?;
    let pool = SshPool::new();
    for name in ["-f", "a;b", "a b", "`x`", "$(x)", "'x'"] {
        let refused = timeout(LIMIT, install(&fake, &pool, name)).await?;
        assert_eq!(
            refused,
            Err(SshError::InvalidArgument(Grammar::PackageName)),
            "{name:?}"
        );
    }
    assert_eq!(fake.handle().counters().connections, 0);
    Ok(())
}

/// Todo 7: service names outside the grammar are refused before any connection.
#[tokio::test]
async fn unknown_service_names_are_refused() -> TestResult {
    let fake = Fake::spawn(config()).await?;
    for name in [
        "nginx",
        "S80nginx; id",
        "S80/../x",
        "S80$(id)",
        "S80nginx start",
    ] {
        assert_eq!(
            ServiceName::parse(name),
            Err(SshError::InvalidArgument(Grammar::ServiceName)),
            "{name:?}"
        );
    }
    assert_eq!(fake.handle().counters().connections, 0);
    Ok(())
}

/// Runs `action` on `name` and reads its result.
// NOT cancel-safe: a dropped action leaves its outcome on the fake unknown.
async fn act(
    session: &Session,
    name: &str,
    action: ServiceAction,
) -> Result<ActionResult, SshError> {
    let command = EntwareCommand::Service(ServiceName::parse(name)?, action);
    let output = session.run(&command).await?;
    parse::action_result(action, &output)
}

/// Todo 7: listing, `check` and the action exit codes as `rc.func` reports them: a
/// disabled service's start and restart exit 8, a failing start 255, stopping a stopped
/// service exits 1.
#[tokio::test]
async fn service_check_semantics_and_exit_8() -> TestResult {
    let fake = Fake::spawn(config()).await?;
    let pool = SshPool::new();
    timeout(LIMIT, async {
        let session = fake.session(&pool, timeouts()).await?;
        let listed = parse::services(&session.run(&EntwareCommand::ListServices).await?)?;
        let names: Vec<&str> = listed.iter().map(ServiceName::as_str).collect();
        assert_eq!(names, ["S51dropbear", "S80nginx", "S90broken", "S99off"]);
        let running = ActionResult::Checked(ServiceState::Running);
        let stopped = ActionResult::Checked(ServiceState::Stopped);
        assert_eq!(
            act(&session, "S51dropbear", ServiceAction::Check).await?,
            running
        );
        assert_eq!(
            act(&session, "S80nginx", ServiceAction::Check).await?,
            stopped
        );
        assert_eq!(
            act(&session, "S80nginx", ServiceAction::Stop).await?,
            ActionResult::AlreadyStopped
        );
        assert_eq!(
            act(&session, "S80nginx", ServiceAction::Start).await?,
            ActionResult::Done
        );
        assert_eq!(
            act(&session, "S80nginx", ServiceAction::Check).await?,
            running
        );
        for action in [ServiceAction::Start, ServiceAction::Restart] {
            let disabled = act(&session, "S99off", action).await;
            assert_eq!(disabled, Err(SshError::ServiceDisabled), "{action:?}");
        }
        let failed = act(&session, "S90broken", ServiceAction::Start).await;
        assert_eq!(failed, Err(SshError::ServiceFailed));
        drop(session);
        TestResult::Ok(())
    })
    .await??;
    assert_eq!(
        fake.handle()
            .service("S99off")
            .map(|service| service.is_running()),
        Some(false)
    );
    Ok(())
}

/// Todo 7: install, upgrade and remove reach opkg with the quoted name and the listings
/// show the result.
#[tokio::test]
async fn package_operations() -> TestResult {
    let fake = Fake::spawn(config()).await?;
    let pool = SshPool::new();
    timeout(LIMIT, async {
        let session = fake.session(&pool, timeouts()).await?;
        let upgradable = parse::upgradable(&session.run(&EntwareCommand::ListUpgradable).await?)?;
        let new_versions: Vec<Option<&str>> = upgradable
            .iter()
            .map(|package| package.new_version.as_deref())
            .collect();
        assert_eq!(new_versions, [Some("2024.10.16~38eccbb1-2")]);
        let mc = PackageName::parse("mc")?;
        let opkg = PackageName::parse("opkg")?;
        for command in [
            EntwareCommand::Update,
            EntwareCommand::Install(mc.clone()),
            EntwareCommand::Upgrade(opkg),
        ] {
            assert_eq!(session.run(&command).await?.exit_status(), 0, "{command:?}");
        }
        assert_eq!(
            fake.handle().installed().get("opkg").map(String::as_str),
            Some("2024.10.16~38eccbb1-2")
        );
        assert_eq!(
            session
                .run(&EntwareCommand::Remove(mc))
                .await?
                .exit_status(),
            0
        );
        drop(session);
        TestResult::Ok(())
    })
    .await??;
    assert!(!fake.handle().installed().contains_key("mc"), "mc removed");
    Ok(())
}
