//! Output limit, timeouts, missing exit status and per-router serialization.

use core::time::Duration;

use kcc_ssh::{
    command::EntwareCommand,
    error::{Phase, SshError},
    grammar::RouterId,
    pool::SshPool,
};
use kcc_testkit::entware_ssh::Fault;
use tokio::time::timeout;

use crate::support::{Fake, LIMIT, TestResult, config, router, timeouts};

/// Todo 7: output over 256 KiB closes the channel with `OutputTruncated`.
#[tokio::test]
async fn output_over_the_limit_is_refused() -> TestResult {
    let fake = Fake::spawn(config()).await?;
    let pool = SshPool::new();
    let result = timeout(LIMIT, async {
        let session = fake.session(&pool, timeouts()).await?;
        fake.handle().set_fault(Some(Fault::HugeOutput));
        let result = session.run(&EntwareCommand::ListInstalled).await;
        drop(session);
        TestResult::Ok(result)
    })
    .await??;
    assert_eq!(result.err(), Some(SshError::OutputTruncated));
    Ok(())
}

/// Todo 7: a hung read ends at the read timeout and a hung mutation at the mutation
/// timeout.
#[tokio::test]
async fn hang_hits_the_command_timeout() -> TestResult {
    let fake = Fake::spawn(config()).await?;
    let pool = SshPool::new();
    let mut short = timeouts();
    short.read = Duration::from_millis(300);
    short.mutation = Duration::from_millis(300);
    let (read, mutation) = timeout(LIMIT, async {
        let session = fake.session(&pool, short).await?;
        fake.handle().set_fault(Some(Fault::Hang));
        let read = session.run(&EntwareCommand::ListInstalled).await;
        let mutation = session.run(&EntwareCommand::Update).await;
        drop(session);
        TestResult::Ok((read, mutation))
    })
    .await??;
    assert_eq!(read.err(), Some(SshError::Timeout(Phase::Read)));
    assert_eq!(mutation.err(), Some(SshError::Timeout(Phase::Mutation)));
    Ok(())
}

/// Todo 7: a channel that closes without an exit status is `NoExitStatus`.
#[tokio::test]
async fn missing_exit_status_is_an_error() -> TestResult {
    let fake = Fake::spawn(config()).await?;
    let pool = SshPool::new();
    let result = timeout(LIMIT, async {
        let session = fake.session(&pool, timeouts()).await?;
        fake.handle().set_fault(Some(Fault::NoExitStatus));
        let result = session.run(&EntwareCommand::ListInstalled).await;
        drop(session);
        TestResult::Ok(result)
    })
    .await??;
    assert_eq!(result.err(), Some(SshError::NoExitStatus));
    Ok(())
}

/// Todo 7: a second session to the same router waits until the first ends and never
/// connects meanwhile; another router is not held up.
#[tokio::test]
async fn sessions_to_one_router_serialize() -> TestResult {
    let fake = Fake::spawn(config()).await?;
    let pool = SshPool::new();
    timeout(LIMIT, async {
        let first = fake.session(&pool, timeouts()).await?;
        let waiting = fake.session(&pool, timeouts());
        tokio::pin!(waiting);
        assert!(
            timeout(Duration::from_millis(300), &mut waiting)
                .await
                .is_err(),
            "the second session waits"
        );
        assert_eq!(
            first
                .run(&EntwareCommand::ListInstalled)
                .await?
                .exit_status(),
            0
        );
        assert_eq!(
            fake.handle().counters().connections,
            1,
            "no second connection yet"
        );
        drop(pool.acquire(&RouterId::parse("office")?).await?);
        drop(first);
        let second = waiting.await?;
        assert_eq!(fake.handle().counters().connections, 2);
        drop(second);
        drop(pool.acquire(&router()?).await?);
        TestResult::Ok(())
    })
    .await??;
    Ok(())
}

/// Todo 7: at most four sessions run at once: a fifth router waits while four other
/// routers hold their slots and proceeds once one of them is released.
#[tokio::test]
async fn a_fifth_router_waits_for_a_global_slot() -> TestResult {
    let pool = SshPool::new();
    timeout(LIMIT, async {
        let mut held = Vec::new();
        for name in ["r1", "r2", "r3", "r4"] {
            held.push(pool.acquire(&RouterId::parse(name)?).await?);
        }
        let fifth = RouterId::parse("r5")?;
        let waiting = pool.acquire(&fifth);
        tokio::pin!(waiting);
        assert!(
            timeout(Duration::from_millis(300), &mut waiting)
                .await
                .is_err(),
            "the fifth router waits"
        );
        drop(held.pop());
        drop(waiting.await?);
        drop(held);
        TestResult::Ok(())
    })
    .await??;
    Ok(())
}
