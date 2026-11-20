# Shared labels used across the Web UI, the CLI and MCP responses.

common-app-name = Keenetic Control Center
common-yes = Yes
common-no = No
common-ok = OK
common-cancel = Cancel
common-save = Save
common-apply = Apply
common-delete = Delete
common-edit = Edit
common-close = Close
common-back = Back
common-enabled = Enabled
common-disabled = Disabled
common-unknown = Unknown
common-language = Language
common-items-count =
    { $count ->
        [one] { $count } item
       *[other] { $count } items
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
common-percent = { $value }%
common-duration-days = { $count } d
common-duration-hours = { $count } h
common-duration-minutes = { $count } min
common-duration-seconds = { $count } s

management-disarm-failed = The management change was applied, but its recovery timer could not be disarmed. Treat the timer as still armed: it may restore the saved configuration and discard all unsaved changes. Check the router before making further changes.

management-outcome-unknown-armed = The management change may or may not have been applied. Its recovery timer stays armed and will restore the saved configuration, discarding all unsaved changes.

management-mode-unknown = kcc can't tell how this router would recover from a lost connection: it reports no usable system mode and no fail-safe timer. Nothing was sent.

management-not-sent-armed = Nothing was changed, but the router may still be counting down to a rollback or reboot. Check the recovery timer before trying again.

management-not-applied = Nothing was applied, and the recovery timer is off.

audit-entry-pending = Done. The audit log is busy; this change's entry will be written as soon as it is free.

management-timer-in-use = Nothing was sent: the router's recovery timer is already running, armed by someone else. kcc leaves that timer to its owner. Commit or disarm it first, then try again.

notify-router-down = [kcc] Router { $router } is offline since { $time }.
notify-router-up = [kcc] Router { $router } is back online after { $duration } offline.
notify-router-login = [kcc] Router { $router } refused kcc's login. Check the password stored for it.
notify-firmware = [kcc] Firmware { $version } is available for router { $router }.
notify-new-devices = [kcc] New unregistered devices on router { $router }: { $devices }.
notify-client-details = { $name } ({ $address })
notify-change-failed = [kcc] Change { $action } on router { $router } by { $actor } failed.
notify-change-failed-fleet = [kcc] Change { $action } by { $actor } failed.
notify-change-fail-safe = The router's fail-safe timer is still armed: unless the change is confirmed, the router restores its saved configuration.
notify-account-locked = [kcc] Account { $user } is locked after failed sign-ins until { $time }.
notify-audit-repaired = [kcc] The audit log was repaired: a torn last entry was moved to { $file }.
notify-audit-stopped = [kcc] The audit writer stopped. kcc serve is shutting down.
notify-job-failed = [kcc] Job { $kind } on router { $router } failed.
notify-job-failed-fleet = [kcc] Job { $kind } failed.
notify-dropped = [kcc] Notifications dropped because they could not be delivered in time: { $count }.
notify-test = [kcc] Test message: notifications reach this chat.
notify-scheduled-done-policy = [kcc] Scheduled action "{ $name }" on router { $router } set connection policy { $policy }.
notify-scheduled-done-backup = [kcc] Scheduled action "{ $name }" on router { $router } backed up the startup configuration.
notify-scheduled-done-reboot = [kcc] Scheduled action "{ $name }" restarted router { $router }; it answers again.
notify-scheduled-failed = [kcc] Scheduled action "{ $name }" on router { $router } failed: { $reason }.
notify-scheduled-skipped = [kcc] Scheduled action "{ $name }" on router { $router } did not run: { $reason }.
notify-scheduled-missed = [kcc] Scheduled action "{ $name }" on router { $router } could not run in time; missed runs: { $count }, the last at { $time }. Missed runs are not made up.
notify-scheduled-paused = [kcc] Scheduled action "{ $name }" on router { $router } was paused: { $reason }.
notify-scheduled-interrupted = [kcc] Scheduled action "{ $name }" on router { $router } was interrupted when kcc stopped and is not run again.
notify-scheduled-unsaved = Not saved; a router restart undoes it.
notify-scheduled-reason-router-busy = the router stayed busy for ten minutes after the scheduled time
notify-scheduled-reason-client-unknown = the client is not registered on the router
notify-scheduled-reason-policy-unknown = the router has no connection policy of that name
notify-scheduled-reason-did-not-come-back = the router did not answer again within 15 minutes
notify-scheduled-reason-preset-unavailable = the preset cannot be applied
notify-scheduled-reason-owner-unavailable = its owner is missing, disabled or no longer covers the router
notify-scheduled-reason-forbidden = its owner's role no longer allows the action
notify-scheduled-reason-router-removed = the router was removed from kcc
notify-scheduled-reason-other = error { $reason }
