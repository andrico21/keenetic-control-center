# Log forwarding

Router log collection is disabled by default. Enable `[logs]` and configure one or more
`[[logs.sinks]]` entries to forward the single collector stream owned for each selected
router. Loki receives bounded `job`, `router`, and `level` labels; process, component, and
record id remain structured metadata to avoid unbounded label cardinality.

For Elasticsearch, install an index template matching `logs-keenetic.syslog-*` and enable
data-stream mode before using the default `logs-keenetic.syslog-default` target. The
template should map `@timestamp` as `date`, `event.id` as `keyword`, `process.pid` as
`long`, and the remaining emitted ECS fields as `keyword` or `text` according to local
search requirements. A custom `target` may select another prepared data stream.

OpenSearch defaults to daily indices named `keenetic-logs-YYYY.MM.DD`. Install an index
template matching `keenetic-logs-*`, including the same timestamp and ECS mappings, and
configure rollover/retention in Index State Management. OpenSearch data streams may also
be used by setting `target` to a separately prepared stream name.

Sink credentials are read from files. Keep those files readable only by the kcc service
account. Delivery retries HTTP 429 and 5xx responses, honours delta-seconds `Retry-After`,
and caps retry delays at 60 seconds. Permanent 4xx item failures are dropped without
blocking accepted items. Inspect the `kcc_log_*` Prometheus counters for received,
forwarded, retried, overflowed, and permanently rejected records.
