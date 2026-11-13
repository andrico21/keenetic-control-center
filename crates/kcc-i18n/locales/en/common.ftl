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
common-refresh = Refresh
common-loading = Loading...
common-search = Search
common-enabled = Enabled
common-disabled = Disabled
common-unknown = Unknown
common-language = Language
common-items-count =
    { $count ->
        [one] { $count } item
       *[other] { $count } items
    }
common-routers-count =
    { $count ->
        [one] { $count } router
       *[other] { $count } routers
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
