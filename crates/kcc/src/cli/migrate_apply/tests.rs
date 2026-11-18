//! The final report of a stopped migration or preset run.

use fluent_bundle::FluentArgs;
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_migrate::apply::ApplyError;

use super::{apply_failure, stopped_report};

/// The exit code, headline, details and armed flag a failure prints.
fn printed(failure: &super::Failure) -> (u8, String, Vec<String>, bool) {
    (
        failure.exit().code(),
        failure.headline(Locale::En),
        failure.details(Locale::En),
        failure.fail_safe_armed(),
    )
}

/// A run whose rollback was proven keeps its exit code and says how many
/// lines were applied before it stopped.
#[test]
fn a_proven_rollback_reports_the_applied_count() {
    let mut args = FluentArgs::new();
    args.set("count", "2");
    for failure in [ApplyError::Stopped, ApplyError::RolledBackByRouter] {
        let (code, _, details, armed) = printed(&stopped_report(failure, 2, false));
        assert_eq!(code, apply_failure(failure).exit().code(), "{failure:?}");
        assert_eq!(
            details,
            [tr(
                Locale::En,
                keys::MIGRATE_APPLY_STOPPED_AFTER,
                Some(&args)
            )],
            "{failure:?}"
        );
        assert!(!armed, "{failure:?}");
    }
}

/// A rollback the router accepted but never proved is reported as such.
///
/// It keeps the failure's exit code and the restarting wording, never that the router
/// is back on its saved configuration.
#[test]
fn a_restarting_rollback_never_claims_the_saved_configuration_is_back() {
    for failure in [
        ApplyError::Stopped,
        ApplyError::RolledBackByRouter,
        ApplyError::Unreachable,
        ApplyError::Verification,
    ] {
        let (code, headline, details, armed) = printed(&stopped_report(failure, 1, true));
        let (mapped_code, mapped_headline, _, _) = printed(&apply_failure(failure));
        assert_eq!(code, mapped_code, "{failure:?}");
        assert_eq!(headline, mapped_headline, "{failure:?}");
        assert_eq!(
            details,
            [tr(Locale::En, keys::MIGRATE_ROLLBACK_SAVED, None)],
            "{failure:?}"
        );
        assert!(!armed, "{failure:?}");
    }
}

/// A failure that may have left the recovery timer armed keeps its own
/// armed report, whatever the rollback said.
#[test]
fn an_armed_fate_keeps_its_own_failure() {
    for failure in [ApplyError::DisarmFailed, ApplyError::FinishFailed] {
        for restarting in [false, true] {
            assert_eq!(
                printed(&stopped_report(failure, 3, restarting)),
                printed(&apply_failure(failure)),
                "{failure:?} {restarting}"
            );
        }
    }
}
