//! Random JSON driven through every tool handler: a typed result or a typed failure, never
//! a panic.

use core::error::Error;

use kcc_app::settings::{McpConfig, PrivacyConfig};
use proptest::{
    prelude::*,
    test_runner::{Config as ProptestConfig, TestCaseResult, TestRunner},
};
use serde_json::Value;

use super::{
    fixture::Fixture,
    strategies::{
        catalog_describe_arguments, catalog_search_arguments, cli_arguments, generated_arguments,
        host_arguments, job_arguments, list_arguments, rci_batch_arguments, rci_read_arguments,
        rci_write_arguments,
    },
};
use crate::{
    KccMcp, McpFailure, config_tools,
    domains::{
        inventory::{READ_TOOLS, WRITE_TOOLS},
        read::read,
        write::dispatch::write,
    },
    generic::{fleet, rci},
    migration_tools::{apply, finish, plan},
};

/// Accepts a serializable value or any typed failure.
fn assert_tool_result(result: Result<Value, McpFailure>) -> TestCaseResult {
    match result {
        Ok(value) => prop_assert!(serde_json::to_vec(&value).is_ok()),
        Err(error) => {
            let typed = matches!(
                error,
                McpFailure::InvalidArguments
                    | McpFailure::Forbidden
                    | McpFailure::ConfirmRequired
                    | McpFailure::DestructiveDisabled
                    | McpFailure::RouterUnreachable
                    | McpFailure::RouterRejected
                    | McpFailure::ManagementAppliedFailSafeArmed
                    | McpFailure::ManagementOutcomeUnknownFailSafeArmed
                    | McpFailure::ManagementAppliedNotSaved
                    | McpFailure::ManagementNotCommittedFailSafeArmed
                    | McpFailure::ValidationFailed
                    | McpFailure::VerificationFailed { field: _ }
                    | McpFailure::Conflict
                    | McpFailure::JobUnavailable
                    | McpFailure::Internal
                    | McpFailure::UnverifiedFirmwareTier
            );
            prop_assert!(typed, "{error:?}");
        }
    }
    Ok(())
}

/// Parses `value` into `T` and, when it parses, runs `call`.
macro_rules! exercise {
    ($value:expr, $input:ty, |$parsed:ident| $call:expr) => {
        if let Ok($parsed) = serde_json::from_value::<$input>($value.clone()) {
            assert_tool_result($call)?;
        }
    };
}

/// The generic tools.
async fn exercise_generic(server: &KccMcp, arguments: &[Value; 9]) -> TestCaseResult {
    let [
        list,
        host,
        search,
        describe,
        read_args,
        write_args,
        batch,
        cli,
        job,
    ] = arguments;
    exercise!(list, fleet::ListInput, |input| fleet::routers_list(
        server, input
    ));
    exercise!(host, fleet::HostInput, |input| fleet::router_info(
        server, input
    )
    .await);
    exercise!(search, fleet::CatalogSearchInput, |input| {
        fleet::catalog_search(server, input).await
    });
    exercise!(describe, fleet::CatalogDescribeInput, |input| {
        fleet::catalog_describe(server, input).await
    });
    exercise!(read_args, rci::RciReadInput, |input| rci::rci_read(
        server, input
    )
    .await);
    exercise!(write_args, rci::RciWriteInput, |input| rci::rci_execute(
        server, input
    )
    .await);
    exercise!(write_args, rci::RciWriteInput, |input| rci::rci_delete(
        server, input
    )
    .await);
    exercise!(batch, rci::RciBatchInput, |input| rci::rci_batch(
        server, input
    )
    .await);
    exercise!(cli, rci::CliInput, |input| rci::cli_parse(server, input)
        .await);
    exercise!(job, fleet::JobInput, |input| fleet::job_status(
        server, input
    ));
    exercise!(job, fleet::JobInput, |input| fleet::job_cancel(
        server, input
    )
    .await);
    assert_tool_result(config_tools::state::config_state(server, host.clone()).await)?;
    assert_tool_result(config_tools::state::config_save(server, host.clone()).await)?;
    Ok(())
}

/// Every registry-generated tool.
async fn exercise_generated(server: &KccMcp, arguments: &Value) -> TestCaseResult {
    for &(area, _name, _toolset, _description) in READ_TOOLS {
        assert_tool_result(read(server, area, arguments.clone()).await)?;
    }
    for &(area, _name, _toolset, _description) in WRITE_TOOLS {
        assert_tool_result(write(server, area, arguments.clone(), None).await)?;
    }
    assert_tool_result(config_tools::backups::create(server, arguments.clone()).await)?;
    assert_tool_result(config_tools::backups::list(server, arguments.clone()))?;
    assert_tool_result(config_tools::backups::diff(server, arguments.clone()))?;
    assert_tool_result(plan::inventory(server, arguments.clone()).await)?;
    assert_tool_result(plan::plan(server, arguments.clone()).await)?;
    assert_tool_result(apply::apply(server, arguments.clone(), None).await)?;
    assert_tool_result(finish::finish(server, arguments.clone()).await)?;
    assert_tool_result(finish::report(server, arguments.clone()).await)?;
    Ok(())
}

#[test]
fn random_json_arguments_never_panic() -> Result<(), Box<dyn Error>> {
    let runtime = tokio::runtime::Runtime::new()?;
    let mut config = McpConfig::default();
    config.toolsets = vec!["core".to_owned(), "raw".to_owned()];
    config.allow_destructive = true;
    let fixture = runtime.block_on(Fixture::spawn(config, PrivacyConfig::default()))?;
    let generic = (
        list_arguments(),
        host_arguments(),
        catalog_search_arguments(),
        catalog_describe_arguments(),
        rci_read_arguments(),
        rci_write_arguments(),
        rci_batch_arguments(),
        cli_arguments(),
        job_arguments(),
    )
        .prop_map(<[Value; 9]>::from);
    let mut runner = TestRunner::new(ProptestConfig::with_cases(256));
    runner.run(
        &(generic, generated_arguments()),
        |(arguments, generated)| {
            runtime.block_on(async {
                exercise_generic(fixture.server(), &arguments).await?;
                exercise_generated(fixture.server(), &generated).await
            })
        },
    )?;
    runtime.block_on(fixture.shutdown())?;
    Ok(())
}
