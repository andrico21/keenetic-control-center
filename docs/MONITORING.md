# Monitoring

kcc can export router metrics to Prometheus and forward router logs to Loki,
Elasticsearch or OpenSearch. Both are off by default and both reuse kcc's own router
sessions: there's no second poller and only one `show log` stream per router.

## Prometheus metrics

Enable the exporter in `kcc.toml` ([CONFIG.md](CONFIG.md#metrics)):

```toml
[metrics]
enabled = true
bind = "127.0.0.1:9090"
```

The `/metrics` listener is plaintext and unauthenticated, so it stays on loopback unless
`allow_non_loopback = true`. Scrapes never contact a router: they render the shared
poller's cache, refreshed every `interval` (light items) and `heavy_interval` (heavy
items). Data older than three intervals is dropped and `keenetic_up` becomes 0.
Per-client series are off by default and capped by `per_client_max`.

Every metric family, with its labels, is listed in [METRICS.md](METRICS.md), generated
from the registry by `cargo xtask gen-metric-docs`; a test fails when it is stale.

Example scrape job:

```yaml
scrape_configs:
  - job_name: kcc
    static_configs:
      - targets: ["127.0.0.1:9090"]
```

In the container the exporter binds inside the container and is published on host
loopback only; see [deploy/podman/README.md](../deploy/podman/README.md).

## Dashboard and alerts

- `deploy/monitoring/grafana-dashboard.json`: import it in Grafana and pick a
  Prometheus and a Loki data source (`DS_PROMETHEUS`, `DS_LOKI`) and a router. Rows:
  fleet overview, system, interfaces, Wi-Fi, clients, VPN and logs.
- `deploy/monitoring/prometheus-alerts.yaml`: rules for a router down, internet
  unreachable, high CPU, low memory, connection tracking nearly full, interface errors,
  fail-safe armed for long, configuration unsaved for a day, and a log sink dropping
  records. `prometheus-alerts.test.yaml` holds `promtool test rules` cases.

## Log forwarding

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

## Data loss

Delivery is at-least-once while kcc runs. There is no disk spool: records still queued
at exit (after a 10-second flush) and records dropped when a sink's queue
(`queue_max`) overflows are lost and counted in `kcc_log_records_dropped_total`. Router
logs are themselves a ring buffer, so records the router discards before kcc reads them
are lost too.
