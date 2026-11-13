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
common-refresh = Aktualisieren
common-loading = Wird geladen...
common-search = Suchen
common-enabled = Aktiviert
common-disabled = Deaktiviert
common-unknown = Unbekannt
common-language = Sprache
common-items-count =
    { $count ->
        [one] { $count } Element
       *[other] { $count } Elemente
    }
common-routers-count =
    { $count ->
        [one] { $count } Router
       *[other] { $count } Router
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
