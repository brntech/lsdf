# End-To-End Demo Flow

```bash
docker compose --profile demo up --build --abort-on-container-exit --exit-code-from demo-runner demo-runner
docker compose run --rm cli init --upstream demo --audit-jsonl-path /workspace/.lsdf/audit.jsonl --metrics-jsonl-path /workspace/.lsdf/metrics.jsonl --output .lsdf.env --force
docker compose up demo-upstream
docker compose --env-file .lsdf.env up gateway
```

Then exercise:

```bash
curl http://localhost:8080/v1/chat/completions -H "content-type: application/json" -d @examples/quickstart/response_redact_request.json
curl -N http://localhost:8080/v1/chat/completions -H "content-type: application/json" -d @examples/quickstart/stream_redact_request.json
docker compose run --rm cli sanitize-observability examples/quickstart/observability.json
docker compose run --rm cli audit-summary .lsdf/audit.jsonl
docker compose run --rm cli metrics-summary .lsdf/metrics.jsonl --format markdown
docker compose --env-file .lsdf.env run --rm cli quickstart-report --gateway-base-url http://host.docker.internal:8080 --audit-jsonl-path .lsdf/audit.jsonl --metrics-jsonl-path .lsdf/metrics.jsonl --format markdown
docker compose run --rm cli proof-bundle --output .lsdf/proof --audit-jsonl-path .lsdf/audit.jsonl --metrics-jsonl-path .lsdf/metrics.jsonl --format markdown
```

The quickstart report reads management status and configured limits, then marks
client protection unverified because it does not send a `/v1` request. Verify a
configured `LSDF_CLIENT_TOKEN` separately with missing, valid, and synthetic
blocked requests before describing caller authentication as active.
