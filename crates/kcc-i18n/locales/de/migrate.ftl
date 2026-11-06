# Machine-assisted translation - native review pending

migrate-title = Konfigurationsmigration
migrate-source = Quellrouter
migrate-target = Zielrouter
migrate-plan = Migrationsplan
migrate-step = Schritt { $current } von { $total }
migrate-unsupported =
    { $count ->
        [one] { $count } Einstellung kann nicht migriert werden
       *[other] { $count } Einstellungen können nicht migriert werden
    }
migrate-start = Migration starten
migrate-done = Migration abgeschlossen.
migrate-rollback = Zurücksetzen
migrate-backup-created = Sicherung der Zielkonfiguration gespeichert.
migrate-reason-copy = Unverändert kopiert.
migrate-reason-remap = Mit der gewählten Zuordnung kopiert.
migrate-reason-skip-hardware = Als Einstellung der Quellhardware übersprungen.
migrate-reason-skip-identity = Als Identität des Quellrouters übersprungen.
migrate-reason-needs-input = Eine Entscheidung des Bedieners ist erforderlich.
migrate-reason-unsupported = Der Zielrouter unterstützt diese Einstellung nicht.
migrate-reason-prune = Nach Auswahl des Bedieners entfernt.
migrate-apply-verified = Migration geprüft. Wählen Sie Speichern oder Zurücksetzen; Änderungen sind noch nicht gespeichert.
migrate-apply-failed = Migration angehalten. Prüfen Sie das Ergebnis vor dem Zurücksetzen.
migrate-apply-router-rollback = Der Router hat nach Ablauf des Wiederherstellungstimers seine gespeicherte Konfiguration wiederhergestellt.
migrate-apply-tier = Bestätigen Sie die Migration auf eine nur anhand der Dokumentation unterstützte Firmware.
migrate-apply-agreement = Bestätigen Sie die aktuelle Routervereinbarung, bevor Sie fortfahren.
migrate-apply-residual = Beibehaltene Einstellungen nur auf dem Zielrouter: { $count }.
