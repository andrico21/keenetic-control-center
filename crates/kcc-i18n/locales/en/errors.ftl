# Errors shown to users. Operator diagnostics stay in logs.

errors-internal = An internal error occurred.
errors-not-found = Not found.
errors-forbidden = You do not have permission to perform this action.
errors-auth-failed = Invalid username or password.
errors-account-locked = Too many failed attempts. Try again in { $minutes } min.
errors-router-unreachable = Router { $name } is unreachable.
errors-router-auth = The router rejected the credentials.
errors-invalid-input = Invalid value for { $field }.
errors-unsupported-firmware = Firmware { $version } is not supported.
errors-timeout = The operation timed out.
errors-csrf = The form has expired. Reload the page and try again.
errors-outbound-refused = kcc does not connect to { $address }: the address is outside the networks of the [outbound] allowed_networks setting. Add the router's network, for example 192.168.1.0/24, to allowed_networks in kcc.toml (or its host name suffix to allowed_suffixes); a running kcc serve picks the change up when restarted. Cloud metadata addresses are always refused.
errors-outbound-metadata = kcc never connects to { $address }: it is a cloud metadata address, which no setting admits.
errors-outbound-loopback = kcc does not connect to { $address }: loopback addresses require [outbound] allow_loopback = true in kcc.toml; a running kcc serve picks the change up when restarted.
errors-outbound-never = kcc never connects to { $address }: no setting admits this kind of address.
