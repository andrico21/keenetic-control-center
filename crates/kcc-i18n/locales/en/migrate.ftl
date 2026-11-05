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
