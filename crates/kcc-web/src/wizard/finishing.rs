//! How a wizard's run ends: the choices step 8 offers, what each needs, and the words of
//! the apply's end.
//!
//! Each wizard keeps its own `Flow::Finish`: the variants differ (a preset run can keep
//! its settings unsaved, a migration commits) and their names are part of the record's
//! on-disk format. The engine reaches the variants it needs through [`Finishing`].

use kcc_app::permissions::Permission;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    locale::Locale,
};
use kcc_migrate::apply::ApplyError;
use serde_json::Value;

use super::{flow::Flow, retention, run::Ended, services::Services};

/// What a rollback needs on the target, in every wizard.
pub(crate) const ROLLBACK: [Permission; 2] = [Permission::Migrate, Permission::Destructive];

/// A choice that finishes applied changes on the router.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Choice {
    /// Disarm the router's timer and save nothing.
    Keep,
    /// Save the verified changes.
    Commit,
    /// Restore the saved configuration.
    Rollback,
}

/// A choice that leaves step 8 without a router request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Settle {
    /// Plan again from the maps, after components were installed.
    Replan,
    /// Back to the preview, after an apply that changed nothing.
    Retry,
    /// Finish an apply with no changes to keep.
    Close,
}

/// A step-8 button that keeps verified changes: the choice it makes, what it posts to
/// under the run's page, its label and its button style, such as `primary`.
pub(crate) type Keeping = (Choice, &'static str, MessageKey, &'static str);

/// How a wizard's run ends: implemented by the wizard's record.
pub(crate) trait Finishing: Flow {
    /// The buttons that keep verified changes, primary first.
    const KEEPING: &'static [Keeping];
    /// Whether an apply that needs a new plan offers to plan again from the maps.
    const REPLANS: bool;
    /// The sentence of a verified apply.
    const VERIFIED: MessageKey;
    /// The sentence of an apply that failed without a recorded reason.
    const FAILED: MessageKey;
    /// The sentence of an apply kcc no longer runs because it restarted.
    const INTERRUPTED: MessageKey;
    /// The sentence under the counts while the changes wait under the timer, if any.
    const WAITING: Option<MessageKey>;
    /// The note shown when the changes wait but the role may not roll them back.
    const ROLLBACK_FORBIDDEN: MessageKey;
    /// The rollback dialog's title and text, both with `$router`.
    const ROLLBACK_WORDS: (MessageKey, MessageKey);
    /// The finish of a rollback the router accepted and restarts for.
    const ROLLBACK_RESTARTING: Self::Finish;
    /// The finish of changes the router's timer rolled back.
    const ROLLED_BACK_BY_ROUTER: Self::Finish;

    /// The audit action, the permissions and the finish of `choice`; none when the
    /// wizard does not offer it.
    fn choice(choice: Choice) -> Option<(&'static str, Vec<Permission>, Self::Finish)>;

    /// The sentence explaining `failure` on the run's pages.
    fn failure_text(failure: ApplyError) -> MessageKey;

    /// The audit parameters of a run that finished `how`, if the wizard records any.
    fn audit_params(_how: Self::Finish) -> Option<Value> {
        None
    }

    /// Plans again, from the maps (`replan`) or from the preview, forgetting an apply
    /// that changed nothing to keep.
    fn plan_anew(&mut self, replan: bool);

    /// Deletes what run `id` sealed once it finished: its source, its copied settings
    /// and its typed passwords.
    // NOT cancel-safe: dropped, the deletions still run to their end.
    async fn discard(services: Services<'_>, id: &str) {
        retention::forget_secrets(&services.store(), id).await;
    }

    /// The sentence explaining the failure a record names `name`; a name this kcc does
    /// not know reads as a failed apply.
    fn recorded_text(name: &str) -> MessageKey {
        ApplyError::from_name(name).map_or(Self::FAILED, Self::failure_text)
    }

    /// How the apply as `ended` records it reads at its end: notice tone and sentence.
    fn ended_words(ended: Option<&Ended>, locale: Locale) -> (&'static str, String) {
        let (tone, key) = match ended {
            Some(found) if found.verified() => ("success", Self::VERIFIED),
            Some(found) => (
                "error",
                found.failure().map_or(Self::FAILED, Self::recorded_text),
            ),
            None => ("error", Self::INTERRUPTED),
        };
        (tone, tr(locale, key, None))
    }
}
