# LSDF Grafana Dashboard

A starter Grafana dashboard for operators ingesting the LSDF gateway's metrics JSONL into Loki. Ten panels mapped one-to-one onto the metric names that LSDF actually emits — no fabricated metrics.

## What it charts

| Panel | Source metric | Notes |
|---|---|---|
| Gateway requests / sec | `gateway_requests_total` | Counter; `stream` label exposed for filtering. |
| Gateway blocks / sec by stage | `gateway_blocks_total` | Counter; grouped by `stage` label (`request_preflight`, `response_inspection`, `stream_response_inspection`, `stream_terminal`). |
| Request inspection latency | `request_inspection_ms` | Duration; p50/p95/max over `$__interval`. |
| Response inspection latency | `response_inspection_ms` | Duration; emitted once per non-streaming response, and once per streaming response when the upstream returned a non-SSE fallback that LSDF re-inspects whole. Per-chunk timing of true SSE streams is in the separate `stream_chunk_inspection_ms` series — see panel 10. |
| Inspection action distribution | `inspection_action_total` | Counter; grouped by (`stage`, `action`). |
| Findings by entity and surface | `inspection_entity_total` and `inspection_surface_total` | Counters; useful for spotting detector-family regressions or surface shift. |
| Upstream errors / sec | `gateway_upstream_errors_total` | Counter; grouped by (`error_type`, `stream`). |
| Upstream open latency (streaming) | `upstream_stream_open_ms` | Duration; the time before the upstream's first streaming byte arrives — spikes here usually mean upstream slowness, not LSDF overhead. |
| Upstream call latency (non-streaming) | `upstream_request_ms` | Duration; full upstream round-trip on the non-streaming path. Companion to the streaming-open panel. |
| Stream chunk inspection latency | `stream_chunk_inspection_ms` | Duration; one observation per holdback-window inspection on true SSE content streams (fires on every content / reasoning delta). The `surface` label breaks out `output.content`, `output.reasoning`, etc. The companion metric `stream_tool_call_inspection_ms` (not on the dashboard by default — add a panel if you run tool-heavy workloads) times the parallel path for tool-call argument-fragment reassembly. |

The dashboard does not invent metrics. If you need a panel for something LSDF doesn't currently emit, add the corresponding `metrics.increment(...)` or `metrics.time_ms(...)` call in `src/lsdf/gateway.py` first, then add the panel.

## Pipeline assumption

The dashboard is built for the Loki / LogQL data path. The expected pipeline:

```
LSDF gateway --> LSDF_METRICS_JSONL_PATH (file) --> log shipper (e.g. Promtail) --> Loki --> Grafana
```

The LogQL queries in the dashboard parse the JSONL via `| json` and filter by `name=`. The required label on each Loki stream is `app=lsdf` (overridable through the `lsdf_app_label` dashboard variable at import time if you ship under a different label).

If you scrape the gateway's `/lsdf/metrics` HTTP endpoint with Prometheus instead of shipping the JSONL through Promtail/Loki, swap each `{app=...} | json | name=...` LogQL query for the equivalent PromQL series — the metric names and labels are the same. The Prometheus text body is served unconditionally when `LSDF_METRICS_ENABLED=true` (no separate Prometheus toggle); the same endpoint returns JSON when called with `?format=json`.

## Importing

1. In Grafana: **Dashboards → New → Import**.
2. Upload `lsdf-dashboard.json` (or paste its contents).
3. Pick your Loki data source on the prompt that follows. The `lsdf_app_label` constant variable defaults to `lsdf`; change it on import if your Loki streams use a different label.
4. Save the dashboard.

The dashboard is self-contained — ten panels, one folder, one variable, no plugins beyond Loki. Adapt the panels' time ranges and refresh interval to match your traffic volume; the defaults (`now-6h`, refresh 30s) suit a low-volume pilot.
