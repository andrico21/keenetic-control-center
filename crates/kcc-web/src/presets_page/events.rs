//! How a run's failed apply reads on the live stream (`crate::wizard::events`) and on the
//! results: the run's own words where they differ from the migration wizard's.

use kcc_i18n::{bundle::MessageKey, keys};
use kcc_migrate::apply::ApplyError;

use crate::wizard::run::failure_text as wizard_text;

/// The sentence explaining `failure` on a run's pages: the run's own words where they
/// differ from the wizard's.
pub(super) const fn failure_text(failure: ApplyError) -> MessageKey {
    match failure {
        ApplyError::Source => keys::WEB_PRESETS_FAILURE_SETTINGS,
        ApplyError::Cancelled => keys::WEB_PRESETS_FAILURE_CANCELLED,
        ApplyError::SameRouter
        | ApplyError::Firmware
        | ApplyError::Workflow
        | ApplyError::Job
        | ApplyError::HardwareMismatch => keys::WEB_PRESETS_FAILURE_FAILED,
        other @ (ApplyError::ReplanRequired
        | ApplyError::UnverifiedFirmwareTier
        | ApplyError::Drift
        | ApplyError::ModeUnknown
        | ApplyError::AgreementRequired
        | ApplyError::PasswordRequired
        | ApplyError::Validation
        | ApplyError::DisarmFailed
        | ApplyError::SavedDisarmFailed
        | ApplyError::ArmUnconfirmed
        | ApplyError::FinishFailed
        | ApplyError::RollbackRestarting
        | ApplyError::CommittedSaveFailed
        | ApplyError::Stopped
        | ApplyError::Verification
        | ApplyError::RolledBackByRouter
        | ApplyError::Unreachable
        | ApplyError::JobStart
        | _) => wizard_text(other),
    }
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use kcc_i18n::{bundle::tr, keys, locale::Locale};
    use kcc_migrate::apply::ApplyError;

    use crate::{
        presets_page::record::Record,
        wizard::{
            finishing::Finishing as _,
            run::{Ended, failure_name},
        },
    };

    /// A run that needs a new plan says so, not that the routers drifted.
    #[test]
    fn a_run_that_needs_a_new_plan_says_so() -> Result<(), serde_json::Error> {
        let name = failure_name(ApplyError::ReplanRequired);
        let ended: Ended = serde_json::from_str(&format!(
            "{{\"at\":2,\"verified\":false,\"failure\":\"{name}\",\"applied\":0,\"failed\":0}}"
        ))?;
        let (tone, words) = Record::ended_words(Some(&ended), Locale::En);
        assert_eq!(tone, "error");
        assert_eq!(words, tr(Locale::En, keys::MIGRATE_APPLY_REPLAN, None));
        Ok(())
    }
}
