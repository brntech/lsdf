# Container Workflow

Date: 2026-04-28

LSDF development, verification, evals, artifact capture, and gateway smoke work should run through Docker Compose. Do not install Python packages, optional detector dependencies, or model tooling into the desktop host environment.

## No Host Installs

- Do not run package installation, Poetry installs, or optional detector setup from the desktop environment.
- Host Python may be used only for incidental file editing by automation when the sandbox shell is broken; LSDF execution and verification should use Docker.
- Docker images, containers, and named volumes are the dependency boundary. Optional detector caches live in Docker volumes.
- Generated host-side Python caches such as `__pycache__/` are disposable and should not be committed.

## Base Dependency-Light Workflow

```bash
docker compose build
docker compose run --rm test
docker compose run --rm cli doctor
docker compose run --rm cli demo
docker compose run --rm cli policy-validate policies/default.yaml
docker compose run --rm cli explain examples/quickstart/request_block.json
docker compose run --rm cli eval evals/basic.json
docker compose run --rm cli compare-detectors evals/safety_matrix.json --format markdown
docker compose run --rm cli optional-detector-artifacts --output-dir docs/artifacts/optional-detectors/2026-04-28
docker compose run --rm cli sanitize-observability examples/observability.json
docker compose run --rm cli audit-summary examples/quickstart/audit.jsonl
docker compose run --rm cli metrics-summary .lsdf/metrics.jsonl --format markdown
docker compose run --rm cli benchmark examples/openai_request.json --iterations 50 --format markdown
docker compose run --rm cli protection-report --format markdown
docker compose run --rm cli simulate-policy evals/basic.json --format markdown
docker compose run --rm cli security-report --format markdown
docker compose run --rm cli proof-bundle --output .lsdf/proof --format markdown
docker compose run --rm cli demo-script --format markdown
docker compose run --rm cli policy explain policies/default.yaml --format markdown
```

Regenerate bundled evaluation fixtures through the Python utility service:

```bash
docker compose run --rm python -m lsdf.eval_matrix --battery all --output-dir /tmp/lsdf-evals
docker compose run --rm python -m unittest discover -s tests -v
```

## Gateway Workflow

Run the canned demo upstream when you want a deterministic quickstart:

```bash
docker compose --profile demo up --build --abort-on-container-exit --exit-code-from demo-runner demo-runner
docker compose run --rm cli init --upstream demo --audit-jsonl-path /workspace/.lsdf/audit.jsonl --metrics-jsonl-path /workspace/.lsdf/metrics.jsonl --output .lsdf.env --force
docker compose up demo-upstream
```

Then run the gateway with the generated env file:

```bash
docker compose --env-file .lsdf.env up gateway
```

Provider presets are available for LiteLLM Proxy and OpenRouter:

```bash
docker compose run --rm cli init --upstream litellm --output .lsdf.env --force
docker compose run --rm cli init --upstream openrouter --output .lsdf.env --force
docker compose --env-file .lsdf.env up gateway
```

```bash
LSDF_UPSTREAM_BASE_URL=http://host.docker.internal:8000 \
  docker compose up gateway
```

The gateway listens on `localhost:8080` on the host and forwards to `/v1/chat/completions` on the configured upstream.

For the demo upstream, use `LSDF_UPSTREAM_BASE_URL=http://demo-upstream:8091` because the gateway runs inside the same Compose network.

Streaming requests with `stream: true` are supported for chat-completion content, reasoning deltas, and streamed tool-call argument deltas. The gateway uses a rolling holdback window before releasing streamed text, assembles fragmented `delta.tool_calls[].function.arguments` by choice/tool-call index before inspection, preserves common SSE metadata, checks all held tails before terminal release, and returns terminal LSDF SSE error events for blocked or malformed upstream streams. If upstream EOF arrives before `[DONE]`, safe held content is flushed before an upstream stream error event; blocked or malformed held tails emit only the terminal error. Configure the text/reasoning holdback with:

```bash
LSDF_STREAM_HOLDBACK_CHARS=512 \
LSDF_UPSTREAM_BASE_URL=http://host.docker.internal:8000 \
  docker compose up gateway
```

Enable durable raw-value-safe gateway telemetry with:

```bash
LSDF_AUDIT_JSONL_PATH=/workspace/.lsdf/audit.jsonl \
LSDF_STREAM_HOLDBACK_CHARS=512 \
LSDF_UPSTREAM_BASE_URL=http://host.docker.internal:8000 \
  docker compose up gateway
```

The JSONL sink records request preflight, non-streaming response inspection/passthrough, and final stream terminal summaries. Stream-time block/error state is recorded there because HTTP response headers cannot be revised after streaming starts. Audit sink writes are best-effort and fail open with raw-value-safe stderr warnings if the sink path is unavailable or unwritable.

Enable raw-value-safe gateway metrics and management endpoints with:

```bash
LSDF_METRICS_ENABLED=true \
LSDF_METRICS_JSONL_PATH=/workspace/.lsdf/metrics.jsonl \
LSDF_UPSTREAM_BASE_URL=http://host.docker.internal:8000 \
  docker compose up gateway
```

Then check:

```bash
curl http://localhost:8080/lsdf/health
curl http://localhost:8080/lsdf/metrics
docker compose run --rm cli metrics-summary .lsdf/metrics.jsonl --format markdown
docker compose run --rm cli quickstart-report --gateway-base-url http://host.docker.internal:8080 --audit-jsonl-path .lsdf/audit.jsonl --metrics-jsonl-path .lsdf/metrics.jsonl --format markdown
```

Set `LSDF_MANAGEMENT_TOKEN` to require a bearer token or `X-LSDF-Management-Token` on `/lsdf/health` and `/lsdf/metrics`. Set `LSDF_MANAGEMENT_ENABLED=false` to disable `/lsdf/*` while keeping `/v1/chat/completions` active.

Use encrypted reversible tokenization only when a vault key and path are configured:

```bash
docker compose run --rm cli vault keygen
```

Set `LSDF_TOKENIZATION_MODE=vault`, `LSDF_VAULT_PATH`, and `LSDF_VAULT_KEY` before starting the gateway. Plaintext token resolution requires `lsdf vault resolve ... --reveal-sensitive-value`.

Vault maintenance stays Docker-only:

```bash
docker compose run --rm cli vault check --vault-path .lsdf/vault.sqlite
docker compose run --rm cli vault backup --vault-path .lsdf/vault.sqlite --output .lsdf/vault.backup.sqlite
docker compose run --rm cli vault rotate-key --vault-path .lsdf/vault.sqlite --old-key-env LSDF_OLD_VAULT_KEY --new-key-env LSDF_NEW_VAULT_KEY --output .lsdf/vault.rotated.sqlite
```

Upstream connection/open/read failures are normalized by the gateway. Before streaming starts, LSDF returns HTTP 502 JSON with `type: upstream_transport_error`. After streaming starts, LSDF flushes safe held state first and then emits a terminal SSE upstream transport error unless the held state itself blocks.

Use the sanitizer CLI for observability payloads outside the proxy:

```bash
docker compose run --rm cli sanitize-observability examples/observability.json
```

Use first-choice developer UX helpers for local setup, explanation, proof, and audit review:

```bash
docker compose run --rm cli init --upstream demo --output .lsdf.env
docker compose run --rm cli explain examples/quickstart/response_redact_request.json --unknown-surface output.content
docker compose run --rm cli audit-summary examples/quickstart/audit.jsonl
docker compose run --rm cli protection-report --format markdown
docker compose run --rm cli audit-export examples/quickstart/audit.jsonl --target generic
docker compose run --rm cli proof-bundle --output .lsdf/proof --format markdown
```

## Optional Detectors

Optional detector dependencies stay in the `optional` Compose profile and Docker-managed volumes:

```bash
docker compose --profile optional build gateway-ml optional-test
docker compose run --rm cli policy-validate --profile broad-pii-ml
docker compose --profile optional run --rm optional-cli doctor --profile broad-pii-ml
LSDF_UPSTREAM_BASE_URL=http://host.docker.internal:8000 \
  docker compose --profile optional up gateway-ml
docker compose --profile optional build optional-test
docker compose --profile optional run --rm optional-test
docker compose --profile optional run --rm optional-cli optional-detector-artifacts --output-dir docs/artifacts/optional-detectors/optional-run
```

The optional privacy-filter path defaults to local-files-only model loading. Use the `lsdf-hf-cache` Docker volume for Hugging Face cache state instead of a desktop Python cache.

`gateway-ml` defaults to `LSDF_PROFILE=broad-pii-ml`, which layers OpenAI privacy-filter with LSDF regex, entropy, and lightweight medical-pattern detectors. It binds the same host port as `gateway`, so run one gateway service at a time unless you intentionally remap ports.

When the privacy-filter model is not cached, `docker compose --profile optional run --rm optional-cli doctor --profile broad-pii-ml` reports a safe detector-unavailable diagnostic. To intentionally prepare the Docker cache, run the same command with `LSDF_OPENAI_PRIVACY_FILTER_LOCAL_FILES_ONLY=false` where model download is allowed.

For release validation with a prepared cache, require the real privacy-filter smoke:

```bash
LSDF_REQUIRE_OPENAI_PRIVACY_FILTER=1 \
  docker compose --profile optional run --rm optional-test
```
