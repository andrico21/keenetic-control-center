//! Read-back rows of the NTP, logging and schedule domains.

use kcc_domain::{RouterCtx, logging, schedules, system};
use kcc_testkit::model::Firmware;

use super::model::{Check, Expect, Field, Row, Step, Steps};

/// The NTP, logging and schedule rows.
pub(crate) const ROWS: &[Row] = &[
    Row::new(
        "ntp.silent_server",
        ntp_server,
        Expect::Silent {
            path: "ntp",
            field: Field::Contains("server"),
        },
    ),
    Row::new("ntp.settings", ntp_settings, Expect::Saved { after: None }),
    Row::new(
        "logging.silent_server",
        log_server,
        Expect::Silent {
            path: "parse",
            field: Field::Contains("log"),
        },
    ),
    Row::new(
        "logging.settings",
        log_settings,
        Expect::Saved { after: None },
    ),
    Row::new(
        "schedules.silent_create",
        schedule_probe,
        Expect::Silent {
            path: "parse",
            field: Field::Contains("schedule"),
        },
    ),
    Row::new(
        "schedules.create",
        schedule_create,
        Expect::Saved {
            after: Some(schedule_listed),
        },
    ),
];

/// The NTP server write.
fn ntp_server(ctx: &RouterCtx, _firmware: Firmware) -> Steps<'_> {
    Box::pin(async move {
        let operation = system::plan_ntp_server(ctx, "192.0.2.67")?;
        Ok(vec![Step::Rci(system::change_request(&operation)?)])
    })
}

/// The server, master and sync-period NTP writes.
fn ntp_settings(ctx: &RouterCtx, _firmware: Firmware) -> Steps<'_> {
    Box::pin(async move {
        let operations = [
            system::plan_ntp_server(ctx, "192.0.2.67")?,
            system::plan_ntp_master(ctx, true)?,
            system::plan_ntp_sync_period(ctx, 67)?,
        ];
        let mut steps = Vec::new();
        for operation in &operations {
            steps.push(Step::Rci(system::change_request(operation)?));
        }
        Ok(steps)
    })
}

/// The remote logging server write.
fn log_server(ctx: &RouterCtx, _firmware: Firmware) -> Steps<'_> {
    Box::pin(async move {
        let operation = logging::plan_server(ctx, "192.0.2.67", Some(514), true)?;
        Ok(vec![Step::Cli(logging::change_request(&operation)?)])
    })
}

/// Logging additions followed by removals.
fn log_settings(ctx: &RouterCtx, _firmware: Firmware) -> Steps<'_> {
    Box::pin(async move {
        let mut steps = Vec::new();
        for enabled in [true, false] {
            let operations = [
                logging::plan_server(ctx, "192.0.2.67", Some(514), enabled)?,
                logging::plan_reduction(ctx, enabled)?,
                logging::plan_suppress(ctx, "Test67", enabled)?,
            ];
            for operation in &operations {
                steps.push(Step::Cli(logging::change_request(operation)?));
            }
        }
        Ok(steps)
    })
}

/// A schedule create whose router answer is ignored.
fn schedule_probe(ctx: &RouterCtx, _firmware: Firmware) -> Steps<'_> {
    Box::pin(async move {
        let operation = schedules::plan_create(ctx, "f4probe")?;
        Ok(vec![Step::Cli(schedules::change_request(&operation)?)])
    })
}

/// A schedule create that the router applies.
fn schedule_create(ctx: &RouterCtx, _firmware: Firmware) -> Steps<'_> {
    Box::pin(async move {
        let operation = schedules::plan_create(ctx, "readback67")?;
        Ok(vec![Step::Cli(schedules::change_request(&operation)?)])
    })
}

/// The created schedule is in the ordinary schedule read.
fn schedule_listed(ctx: &RouterCtx) -> Check<'_> {
    Box::pin(async move {
        let rows = schedules::read_schedules(ctx).await?;
        Ok(rows
            .iter()
            .any(|row| row.name.as_deref() == Some("readback67")))
    })
}
