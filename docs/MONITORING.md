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

The exporter follows the router registry: a router added or removed while kcc runs (Web
UI, or `kcc router add|remove` followed by `SIGHUP`) is scraped or dropped without a
restart. `keenetic_firmware_update_available` appears once kcc has checked the router
for newer firmware (`components check-update`, at most every six hours per router, only
while its polls succeed). `kcc_web_sessions` counts signed-in Web UI sessions, sampled
every 15 seconds.

Every metric family, with its labels, is listed in [METRICS.md](METRICS.md), generated
from the registry by `cargo xtask gen-metric-docs`; a test fails when it is stale.

`/readyz` reports `audit_alive: false` while the audit writer is unavailable. A fatal
audit-writer error also terminates `kcc serve` with a non-zero status, so the shipped
Quadlet `Restart=on-failure` policy starts a fresh process instead of leaving an
unhealthy daemon running. Cross-process append-lock contention never terminates the
writer and never drops an entry: an entry whose lock stays busy is kept at the head of
the queue and retried until the lock is free, with a `warn` log line ("audit append lock
still held by another process") every round of about 25 s. Callers wait for their entry
only a bounded time: 30 s for an ordinary change, 20 s after the disarm for a management
change's recovery bracket, 5 s for a Web sign-in. A change the router applied whose entry
is still queued then is reported as done with the `audit-entry-pending` note (CLI exit
0, MCP `"audit_pending": true`, a Web success toast). When `kcc serve` or `kcc mcp
stdio` exits, the writer gets at most 5 s to write what is still queued; the count of
entries lost then is logged at `error` level ("audit entries still queued at exit are
lost"). A CLI run exits right after its change, so an entry still queued then is lost
with it.

Before it exits on a dead audit writer, `kcc serve` shuts its listener down the way
SIGTERM does: it stops accepting connections and lets the requests in flight finish and
answer, within `server.shutdown_timeout` (30 s by default). A Web request that has sent
a write to a router is never cut by the 30-second request budget or a closed browser
connection: it ends and is audited. A request on any surface (Web UI, MCP over HTTP or
stdio) that has armed a router's fail-safe timer is not cut by this shutdown either: it
still disarms the timer and reports, or reports that the timer stays armed. After the
listener has stopped, on either path, `kcc serve` waits up to 10 more seconds for such
requests, as `kcc mcp stdio` does once its input closes, and logs `requests still
closing a router fail-safe bracket at exit` with their number if any remain; their
routers then roll back on their own timers. Set the Quadlet `StopTimeout` to at least `server.shutdown_timeout` plus 45 seconds: the bracket grace period (10 s), the job drain (30 s), and the audit flush wait (5 s). This is 80 s as shipped.

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
router by the long-lived `kcc serve` process; `kcc mcp stdio` does not start collectors or
sinks. Loki receives bounded `job`, `router`, and `level` labels; process, component, and
record id remain structured metadata to avoid unbounded label cardinality. The Web UI log
page of a collected router follows the same stream (the latest 200 records, then new
ones), so log viewers add no router requests.

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
account. Sinks connect directly: the `HTTP_PROXY`, `HTTPS_PROXY` and `ALL_PROXY`
environment variables are ignored. Delivery retries HTTP 429 and 5xx responses, honours delta-seconds `Retry-After`,
and caps retry delays at 60 seconds. Permanent 4xx item failures are dropped without
blocking accepted items. Inspect the `kcc_log_*` Prometheus counters for received,
forwarded, retried, overflowed, and permanently rejected records.

## Data loss

Delivery is at-least-once while kcc runs. There is no disk spool: records still queued
at exit (after a 10-second flush) and records dropped when a sink's queue
(`queue_max`) overflows are lost and counted in `kcc_log_records_dropped_total`. Router
logs are themselves a ring buffer, so records the router discards before kcc reads them
are lost too.
