# Privacy

Router logs can contain client MAC addresses, host names, addresses, account names, and
other operational data supplied by the router or its clients. Forwarding sends this data
to the configured external sink, where that sink's access and retention policies apply.

Set `[logs] redact_macs = true` when stable hardware addresses are not needed in the
destination. This option redacts MAC addresses before records are broadcast to subscribers
or queued for sinks. It does not remove other identifiers from free-form router messages;
operators should restrict sink access and choose an appropriate retention period.

Passwords, bearer tokens, and API keys are loaded from configured files and are excluded
from kcc `Debug`, error, and tracing output. They are still transmitted to the selected
sink as HTTP authentication material, so use HTTPS outside loopback and protect the
credential files.
