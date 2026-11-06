# Configuration migration between routers.

migrate-title = Configuration migration
migrate-source = Source router
migrate-target = Target router
migrate-plan = Migration plan
migrate-step = Step { $current } of { $total }
migrate-unsupported =
    { $count ->
        [one] { $count } setting cannot be migrated
       *[other] { $count } settings cannot be migrated
    }
migrate-start = Start migration
migrate-done = Migration finished.
migrate-rollback = Roll back
migrate-backup-created = Backup of the target configuration saved.
migrate-reason-copy = Copied unchanged.
migrate-reason-remap = Copied with an operator-approved mapping.
migrate-reason-skip-hardware = Skipped because it belongs to source hardware.
migrate-reason-skip-identity = Skipped because it belongs to source identity.
migrate-reason-needs-input = Operator input is required.
migrate-reason-unsupported = The target does not support this setting.
migrate-reason-prune = Removed by operator selection.
migrate-apply-verified = Migration verified. Choose commit or rollback; changes are not saved yet.
migrate-apply-failed = Migration stopped. Review the result before choosing rollback.
migrate-apply-router-rollback = The router restored its saved configuration after the recovery timer expired.
migrate-apply-tier = Confirm migration to firmware supported from documentation only.
migrate-apply-agreement = Confirm the current router agreement before continuing.
migrate-apply-residual = Target-only settings retained: { $count }.
