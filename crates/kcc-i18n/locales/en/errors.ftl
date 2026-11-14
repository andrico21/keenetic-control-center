# Errors shown to users. Operator diagnostics stay in logs.

errors-forbidden = You do not have permission to perform this action.
errors-auth-failed = Invalid username or password.
errors-router-auth = The router rejected the credentials.
errors-timeout = The operation timed out.
errors-outbound-refused = kcc does not connect to { $address }: the address is outside the networks of the [outbound] allowed_networks setting. Add the router's network, for example 192.168.1.0/24, to allowed_networks in kcc.toml (or its host name suffix to allowed_suffixes); a running kcc serve picks the change up when restarted. Cloud metadata addresses are always refused.
errors-outbound-metadata = kcc never connects to { $address }: it is a cloud metadata address, which no setting admits.
errors-outbound-loopback = kcc does not connect to { $address }: loopback addresses require [outbound] allow_loopback = true in kcc.toml; a running kcc serve picks the change up when restarted.
errors-outbound-never = kcc never connects to { $address }: no setting admits this kind of address.
errors-secret-file-permissions = { $path } can be read by other users. Run chmod 600 { $path } and try again.
