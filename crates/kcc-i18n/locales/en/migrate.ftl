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
