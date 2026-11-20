# Machine-assisted translation - native review pending

common-app-name = Keenetic Control Center
common-yes = Ja
common-no = Nein
common-ok = OK
common-cancel = Abbrechen
common-save = Speichern
common-apply = Übernehmen
common-delete = Löschen
common-edit = Bearbeiten
common-close = Schließen
common-back = Zurück
common-enabled = Aktiviert
common-disabled = Deaktiviert
common-unknown = Unbekannt
common-language = Sprache
common-items-count =
    { $count ->
        [one] { $count } Element
       *[other] { $count } Elemente
    }
common-unit-bytes = { $value } B
common-unit-kilobytes = { $value } KB
common-unit-megabytes = { $value } MB
common-unit-gigabytes = { $value } GB
common-unit-terabytes = { $value } TB
common-unit-bits = { $value } bit/s
common-unit-kilobits = { $value } kbit/s
common-unit-megabits = { $value } Mbit/s
common-unit-gigabits = { $value } Gbit/s
common-percent = { $value } %
common-duration-days = { $count } Tg.
common-duration-hours = { $count } Std.
common-duration-minutes = { $count } Min.
common-duration-seconds = { $count } Sek.

management-disarm-failed = Die Änderung der Verwaltungseinstellungen wurde angewendet, aber der Wiederherstellungstimer konnte nicht deaktiviert werden. Behandeln Sie den Timer als weiterhin aktiv: Er kann die gespeicherte Konfiguration wiederherstellen und alle ungespeicherten Änderungen verwerfen. Prüfen Sie den Router vor weiteren Änderungen.

management-outcome-unknown-armed = Es ist unklar, ob die Änderung der Verwaltungseinstellungen angewendet wurde. Der Wiederherstellungstimer bleibt aktiv und wird die gespeicherte Konfiguration wiederherstellen und alle ungespeicherten Änderungen verwerfen.

management-mode-unknown = kcc kann nicht erkennen, wie sich dieser Router nach einem Verbindungsverlust wiederherstellen würde: Er meldet weder einen verwendbaren Betriebsmodus noch einen Fail-safe-Timer. Es wurde nichts gesendet.

management-not-sent-armed = Es wurde nichts geändert, aber der Router zählt möglicherweise noch bis zu einem Rollback oder Neustart herunter. Prüfen Sie den Wiederherstellungstimer, bevor Sie es erneut versuchen.

management-not-applied = Es wurde nichts übernommen, und der Wiederherstellungstimer ist aus.

audit-entry-pending = Erledigt. Das Audit-Protokoll ist belegt; der Eintrag zu dieser Änderung wird geschrieben, sobald es frei ist.

management-timer-in-use = Es wurde nichts gesendet: Der Wiederherstellungstimer des Routers läuft bereits, von jemand anderem gestellt. kcc überlässt diesen Timer seinem Besitzer. Bestätigen oder deaktivieren Sie ihn zuerst und versuchen Sie es dann erneut.

notify-router-down = [kcc] Router { $router } ist seit { $time } nicht erreichbar.
notify-router-up = [kcc] Router { $router } ist wieder erreichbar; er war { $duration } nicht erreichbar.
notify-router-login = [kcc] Router { $router } hat die Anmeldung von kcc abgelehnt. Prüfen Sie das für ihn gespeicherte Passwort.
notify-firmware = [kcc] Für Router { $router } ist die Firmware { $version } verfügbar.
notify-new-devices = [kcc] Neue nicht registrierte Geräte an Router { $router }: { $devices }.
notify-client-details = { $name } ({ $address })
notify-change-failed = [kcc] Die Änderung { $action } an Router { $router } durch { $actor } ist fehlgeschlagen.
notify-change-failed-fleet = [kcc] Die Änderung { $action } durch { $actor } ist fehlgeschlagen.
notify-change-fail-safe = Der Wiederherstellungstimer des Routers läuft noch: Wird die Änderung nicht bestätigt, stellt der Router seine gespeicherte Konfiguration wieder her.
notify-account-locked = [kcc] Das Konto { $user } ist nach fehlgeschlagenen Anmeldungen bis { $time } gesperrt.
notify-audit-repaired = [kcc] Das Audit-Protokoll wurde repariert: Ein abgeschnittener letzter Eintrag wurde nach { $file } verschoben.
notify-audit-stopped = [kcc] Der Audit-Schreiber wurde beendet. kcc serve fährt herunter.
notify-job-failed = [kcc] Der Auftrag { $kind } an Router { $router } ist fehlgeschlagen.
notify-job-failed-fleet = [kcc] Der Auftrag { $kind } ist fehlgeschlagen.
notify-dropped = [kcc] Benachrichtigungen, die nicht rechtzeitig zugestellt werden konnten, wurden verworfen: { $count }.
notify-test = [kcc] Testnachricht: Benachrichtigungen erreichen diesen Chat.
notify-scheduled-done-policy = [kcc] Die geplante Aktion „{ $name }“ hat an Router { $router } die Verbindungsrichtlinie { $policy } gesetzt.
notify-scheduled-done-backup = [kcc] Die geplante Aktion „{ $name }“ hat die Startkonfiguration von Router { $router } gesichert.
notify-scheduled-done-reboot = [kcc] Die geplante Aktion „{ $name }“ hat Router { $router } neu gestartet; er antwortet wieder.
notify-scheduled-failed = [kcc] Die geplante Aktion „{ $name }“ an Router { $router } ist fehlgeschlagen: { $reason }.
notify-scheduled-skipped = [kcc] Die geplante Aktion „{ $name }“ an Router { $router } wurde nicht ausgeführt: { $reason }.
notify-scheduled-missed = [kcc] Die geplante Aktion „{ $name }“ an Router { $router } konnte nicht rechtzeitig laufen; verpasste Läufe: { $count }, der letzte um { $time }. Verpasste Läufe werden nicht nachgeholt.
notify-scheduled-paused = [kcc] Die geplante Aktion „{ $name }“ an Router { $router } wurde angehalten: { $reason }.
notify-scheduled-interrupted = [kcc] Die geplante Aktion „{ $name }“ an Router { $router } wurde beim Beenden von kcc unterbrochen und wird nicht wiederholt.
notify-scheduled-unsaved = Nicht gespeichert; ein Neustart des Routers macht die Änderung rückgängig.
notify-scheduled-reason-router-busy = der Router war bis zehn Minuten nach der geplanten Zeit belegt
notify-scheduled-reason-client-unknown = der Client ist am Router nicht registriert
notify-scheduled-reason-policy-unknown = der Router hat keine Verbindungsrichtlinie dieses Namens
notify-scheduled-reason-did-not-come-back = der Router hat innerhalb von 15 Minuten nicht wieder geantwortet
notify-scheduled-reason-preset-unavailable = die Vorlage kann nicht angewendet werden
notify-scheduled-reason-owner-unavailable = ihr Besitzer fehlt, ist deaktiviert oder umfasst den Router nicht mehr
notify-scheduled-reason-forbidden = die Rolle ihres Besitzers erlaubt die Aktion nicht mehr
notify-scheduled-reason-router-removed = der Router wurde aus kcc entfernt
notify-scheduled-reason-other = Fehler { $reason }
