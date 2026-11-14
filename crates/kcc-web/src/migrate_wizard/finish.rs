//! How a migration ends.
//!
//! Commit keeps the verified changes, Replan plans again from the maps when the apply
//! needs a new plan; the migration names its words for step 8 and its rollback (the
//! shared step is `crate::wizard::finish`).

use kcc_app::permissions::Permission;
use kcc_i18n::{bundle::MessageKey, keys};
use kcc_migrate::apply::ApplyError;

use super::{
    kinds::{Finish, Step},
    preview::commit_permissions,
    record::Record,
};
use crate::wizard::{
    finishing::{Choice, Finishing, Keeping, ROLLBACK},
    run::failure_text,
};

impl Finishing for Record {
    const KEEPING: &'static [Keeping] = &[(
        Choice::Commit,
        "commit",
        keys::WEB_MIGRATE_COMMIT,
        "primary",
    )];
    const REPLANS: bool = true;
    const VERIFIED: MessageKey = keys::MIGRATE_APPLY_VERIFIED;
    const FAILED: MessageKey = keys::MIGRATE_APPLY_FAILED;
    const INTERRUPTED: MessageKey = keys::WEB_MIGRATE_RUN_INTERRUPTED;
    const WAITING: Option<MessageKey> = None;
    const ROLLBACK_FORBIDDEN: MessageKey = keys::WEB_MIGRATE_ROLLBACK_FORBIDDEN;
    const ROLLBACK_WORDS: (MessageKey, MessageKey) = (
        keys::WEB_MIGRATE_ROLLBACK_TITLE,
        keys::WEB_MIGRATE_ROLLBACK_TEXT,
    );
    const ROLLBACK_RESTARTING: Finish = Finish::RollbackRestarting;
    const ROLLED_BACK_BY_ROUTER: Finish = Finish::RolledBackByRouter;

    fn choice(choice: Choice) -> Option<(&'static str, Vec<Permission>, Finish)> {
        match choice {
            Choice::Commit => Some((
                "web.migrate_commit",
                commit_permissions(),
                Finish::Committed,
            )),
            Choice::Rollback => Some((
                "web.migrate_rollback",
                ROLLBACK.to_vec(),
                Finish::RolledBack,
            )),
            Choice::Keep => None,
        }
    }

    fn failure_text(failure: ApplyError) -> MessageKey {
        failure_text(failure)
    }

    fn plan_anew(&mut self, replan: bool) {
        self.plan_again(if replan { Step::Mapping } else { Step::Preview });
    }
}
