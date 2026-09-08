# LSDF Quickstart Examples

These payloads drive the five-minute LSDF demo path:

All sensitive-looking strings in this directory are synthetic LSDF fixtures. They are shaped to exercise detectors but are not real credentials, patient records, or customer data.

- `request_block.json`: unsafe request blocked before the model.
- `response_redact_request.json`: safe request with an unsafe upstream response that LSDF redacts.
- `stream_redact_request.json`: streamed unsafe content redacted before release.
- `tool_call_block_request.json`: streamed tool-call arguments blocked before raw fragments reach the client.
- `observability.json`: trace/log-style payload sanitized through `logs.traces`.
- `audit.jsonl`: raw-value-safe example audit line for `lsdf audit-summary`.

Complete [Installation](../../docs/installation.md) first, including Docker setup and downloading or cloning the source. Run the commands below from the repository root containing `docker-compose.yml`, not from this examples directory.

These examples use the source checkout and its local development image. The prebuilt runtime image runs the standalone gateway; use `compose.release.yaml` and the installation guide for that path.

Build the development image, then run the examples through Docker Compose:

```bash
docker compose build cli
docker compose run --rm cli demo
docker compose run --rm cli explain examples/quickstart/request_block.json
docker compose run --rm cli sanitize-observability examples/quickstart/observability.json
docker compose run --rm cli audit-summary examples/quickstart/audit.jsonl
```

For the full HTTP and streaming demonstration, including its own upstream and gateway:

```bash
docker compose --profile demo up --build --abort-on-container-exit --exit-code-from demo-runner demo-runner
docker compose --profile demo down
```

The runner reports safe aggregate results and exits. See [Container Workflow](../../docs/container-workflow.md#gateway-workflow) to keep a demo gateway running for your own client.
