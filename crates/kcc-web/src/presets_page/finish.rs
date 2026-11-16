//! How a preset run ends.
//!
//! Keep unsaved disarms the router's fail-safe timer and saves nothing, Save on the
//! router saves the verified settings; the run names its words for step 8 and its
//! rollback (the shared step is `crate::wizard::finish`). Finishing deletes what the run
//! sealed: the copied settings and the typed passwords.

use kcc_app::permissions::Permission;
use kcc_i18n::{bundle::MessageKey, keys};
use kcc_migrate::apply::ApplyError;
use serde_json::{Value, json};

use super::{events::failure_text, record::Record, steps::Finish};
use crate::wizard::finishing::{Choice, Finishing, Keeping, ROLLBACK};

/// What keeping the settings unsaved needs on the target: disarming the timer.
const KEEP: [Permission; 2] = [Permission::Migrate, Permission::Write];

/// What saving the settings needs on the target.
const SAVE: [Permission; 2] = [Permission::Migrate, Permission::Save];

impl Finishing for Record {
    const KEEPING: &'static [Keeping] = &[
        (Choice::Keep, "keep", keys::WEB_PRESETS_KEEP, "primary"),
        (
            Choice::Commit,
            "save",
            keys::WEB_PRESETS_SAVE_ROUTER,
            "secondary",
        ),
    ];
    const REPLANS: bool = false;
    const VERIFIED: MessageKey = keys::WEB_PRESETS_APPLIED;
    const FAILED: MessageKey = keys::WEB_PRESETS_FAILURE_FAILED;
    const INTERRUPTED: MessageKey = keys::WEB_PRESETS_RUN_INTERRUPTED;
    const WAITING: Option<MessageKey> = Some(keys::WEB_PRESETS_RESULTS_TEXT);
    const ROLLBACK_FORBIDDEN: MessageKey = keys::WEB_PRESETS_ROLLBACK_FORBIDDEN;
    const ROLLBACK_WORDS: (MessageKey, MessageKey) = (
        keys::WEB_PRESETS_ROLLBACK_TITLE,
        keys::WEB_PRESETS_ROLLBACK_TEXT,
    );
    const ROLLBACK_RESTARTING: Finish = Finish::RollbackRestarting;
    const ROLLED_BACK_BY_ROUTER: Finish = Finish::RolledBackByRouter;

    fn choice(choice: Choice) -> Option<(&'static str, Vec<Permission>, Finish)> {
        let (action, needed, finish) = match choice {
            Choice::Keep => ("web.preset_keep", KEEP, Finish::KeptUnsaved),
            Choice::Commit => ("web.preset_save", SAVE, Finish::Saved),
            Choice::Rollback => ("web.preset_rollback", ROLLBACK, Finish::RolledBack),
        };
        Some((action, needed.to_vec(), finish))
    }

    fn failure_text(failure: ApplyError) -> MessageKey {
        failure_text(failure)
    }

    fn audit_params(how: Finish) -> Option<Value> {
        Some(json!({ "finish": how.slug() }))
    }

    fn plan_anew(&mut self, _replan: bool) {
        self.plan_again();
    }
}
