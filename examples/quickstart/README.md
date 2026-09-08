# LSDF Quickstart Examples

These payloads drive the five-minute LSDF demo path:

All sensitive-looking strings in this directory are synthetic LSDF fixtures. They are shaped to exercise detectors but are not real credentials, patient records, or customer data.

- `request_block.json`: unsafe request blocked before the model.
- `response_redact_request.json`: safe request with an unsafe upstream response that LSDF redacts.
- `stream_redact_request.json`: streamed unsafe content redacted before release.
- `tool_call_block_request.json`: streamed tool-call arguments blocked before raw fragments reach the client.
- `observability.json`: trace/log-style payload sanitized through `logs.traces`.
- `audit.jsonl`: raw-value-safe example audit line for `lsdf audit-summary`.

Run them through Docker Compose, for example:

```bash
docker compose run --rm cli demo
docker compose run --rm cli explain examples/quickstart/request_block.json
docker compose run --rm cli sanitize-observability examples/quickstart/observability.json
docker compose run --rm cli audit-summary examples/quickstart/audit.jsonl
```
