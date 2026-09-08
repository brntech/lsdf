# Production Operations

Updated: 2026-09-08

Provider rollout material covers LiteLLM Proxy, OpenRouter, LM Studio, local vLLM, and generic OpenAI-compatible upstreams. Use `docs/provider-playbook.md` for topology choices, and keep the recommended LiteLLM flow as `app -> LSDF gateway -> LiteLLM Proxy -> provider fleet`.

Start with [Installation](installation.md) for prerequisites and the published-image path. Commands below use a source checkout unless stated otherwise. Start the upstream separately, with an address reachable from Docker, and supply its credentials through `LSDF_UPSTREAM_API_KEY` when required.

LSDF now exposes raw-value-safe operational surfaces while keeping OpenAI-compatible `/v1/*` behavior unchanged.

## Standalone Runtime Image

The lightweight `runtime` target starts the gateway on port 8080. It includes LSDF source, policies, required synthetic policy-validation fixtures, and three first-party proof matrices. It does not include development test code, external benchmark corpora, model weights, or heavy detector dependencies. The existing `base` and `optional-detectors` targets support repository development and evaluation.

Build and run from a source checkout without mounting that checkout into the gateway:

```bash
LSDF_UPSTREAM_BASE_URL=http://host.docker.internal:8000 \
  docker compose --profile runtime up --build runtime
```

Point clients on the host at `http://localhost:8080/v1`. This local recipe binds the host port to loopback. The service forwards the same gateway settings as the development gateway. Its named volume persists `/workspace/.lsdf` for configured audit, metrics, proof, and encrypted vault files; use paths inside that directory. Custom policy files need an explicit read-only mount and policy argument. For a real upstream, supply `LSDF_UPSTREAM_API_KEY` through the environment when required.

For shared access, place the gateway behind ingress authentication, TLS, and network access controls. LSDF does not authenticate client chat requests. `LSDF_MANAGEMENT_TOKEN` protects only `/lsdf/*`; the upstream API key authenticates LSDF to the provider and does not protect LSDF's client endpoint.

The image accepts CLI arguments, for example `docker compose --profile runtime run --rm runtime doctor --profile default`. Proof commands work in the runtime; place their output under `.lsdf/` to persist it in this recipe's named volume. Full benchmark evaluation and the live demo runner use the development Compose services and source checkout. A standalone Python wheel is not the supported distribution path: policy assets currently depend on the container's repository layout.

The source `gateway` and `cli` services share the checkout's `.lsdf/` directory. The `runtime` service uses a named volume instead: source `cli` commands cannot see its audit files or vault. For runtime maintenance, use the same service and Compose configuration as the deployed gateway, such as `docker compose --profile runtime run --rm runtime metrics-summary .lsdf/metrics.jsonl --format markdown`. Published-image deployments likewise need their own persistent volume attached to maintenance containers. A container path such as `/workspace/.lsdf/audit.jsonl` is not a host checkout path.

From v0.3.1, the release workflow publishes `ghcr.io/brntech/lsdf:vX.Y.Z` and `:vX.Y.Z-ml`. Pin a verified digest for deployment. Both runtime images start with the dependency-light `default` profile. Select `LSDF_PROFILE=broad-pii-ml` explicitly only after mounting and preparing the model cache and checking `doctor --profile broad-pii-ml`. The `runtime-optional` target contains heavier dependencies and the spaCy language model; GLiNER and privacy-filter weights still require an explicit model-cache setup. Third-party licenses remain separate from LSDF's Apache-2.0 license; see `THIRD_PARTY_NOTICES.md`. An optional image build alone does not establish model readiness or recall.

## Optional ML Gateway

Use `gateway-ml` for the Docker-managed `broad-pii-ml` profile. First complete [Optional ML installation](installation.md#optional-ml): GLiNER and privacy-filter both need a prepared cache. The optional image alone does not provide their weights.

```bash
docker compose --profile optional build gateway-ml
docker compose run --rm cli policy-validate --profile broad-pii-ml
docker compose --profile optional run --rm optional-cli doctor --profile broad-pii-ml --format json
docker compose run --rm cli init --upstream vllm --profile broad-pii-ml --output .lsdf.env --force
docker compose --env-file .lsdf.env --profile optional up gateway-ml
```

This path uses heavier optional dependencies and the `lsdf-hf-cache` Docker volume. Keep the default gateway for dependency-light local pilots. `broad-pii-ml` always includes the local broad-pii stack; OpenAI privacy-filter is an optional reference family that is used when loadable and skipped when unavailable. The optional image keeps GLiNER and OpenAI privacy-filter in separate Python dependency stacks so their incompatible Transformers requirements do not collide.

Missing required GLiNER prevents startup. Missing optional privacy-filter does not necessarily make doctor fail: verify that the JSON detector-family list includes both `gliner` and `openai_privacy_filter` before claiming that the combined ML stack is ready. `policy-validate` checks policy structure and coverage, not model readiness. The example replaces `.lsdf.env`; retain any existing credentials, telemetry, or domain-pack settings, and check shell overrides when changing profiles.

The privacy-filter worker handles one exchange at a time. Its 60-second inference budget includes queueing; measure and tune it for large payloads and concurrent traffic. Replacing a failed worker has a separate 300-second startup budget, which can cause queued callers to time out. Timeouts halt inspection with HTTP 500 `inspection_error` before headers, or a terminal SSE error afterward; enabled audit and metrics record the failure. They do not degrade to the local detector stack. See [worker settings and recovery behavior](installation.md#optional-ml).

For release validation, regenerate the gate report:

```bash
docker compose --profile optional run --rm optional-cli eval-report --profile broad-pii --profile broad-pii-ml --format markdown
```

## Gateway Health And Metrics

For the source-checkout gateway, create a configuration with both audit and metrics enabled. This example replaces `.lsdf.env`; preserve any existing local settings you need.

```bash
docker compose run --rm cli init --upstream vllm --profile default \
  --audit-jsonl-path /workspace/.lsdf/audit.jsonl \
  --metrics-jsonl-path /workspace/.lsdf/metrics.jsonl \
  --output .lsdf.env --force
docker compose --env-file .lsdf.env up -d gateway
```

Send representative chat traffic through the gateway, then check health and metrics. Telemetry summaries require files produced by traffic; configuration generation alone does not create them. Run the CLI commands from the same checkout so `gateway:8080` resolves on its Compose network.

```bash
curl http://localhost:8080/lsdf/health
curl http://localhost:8080/lsdf/metrics
curl "http://localhost:8080/lsdf/metrics?format=json"
docker compose run --rm cli metrics-summary .lsdf/metrics.jsonl --format markdown
docker compose run --rm cli smoke --gateway-base-url http://gateway:8080
docker compose run --rm cli quickstart-report --gateway-base-url http://gateway:8080 --audit-jsonl-path .lsdf/audit.jsonl --metrics-jsonl-path .lsdf/metrics.jsonl --format markdown
```

Metrics contain counts, durations, surfaces, entities, actions, detector families, stream states, status/error types, and no payload text.

Management endpoints are enabled by default for local compatibility. In shared environments, set `LSDF_MANAGEMENT_TOKEN` so `/lsdf/health` and `/lsdf/metrics` require `Authorization: Bearer <token>` or `X-LSDF-Management-Token`. Set `LSDF_MANAGEMENT_ENABLED=false` to disable `/lsdf/*` entirely; `/v1/*` remains unchanged.

For token-protected endpoints, use authenticated requests, for example:

```bash
curl -H "X-LSDF-Management-Token: $LSDF_MANAGEMENT_TOKEN" http://localhost:8080/lsdf/health
curl -H "X-LSDF-Management-Token: $LSDF_MANAGEMENT_TOKEN" http://localhost:8080/lsdf/metrics
```

The built-in `smoke` and `quickstart-report` commands do not send management tokens; their endpoint checks apply to the unprotected local setup above. A disabled management endpoint returns 404 even through a reverse proxy. Health HTTP 200 alone also does not establish upstream readiness: inspect the response's `status` and `upstream` fields and validate a real chat request.

## Inspection failures

A policy `on_fail: exception` halts request preflight with HTTP 403 or response inspection with HTTP 502; both use `policy_enforcement_error`. Other local inspection failures return HTTP 500 with `inspection_error`. Bodies contain fixed messages, not detector, vault, or operator exception text. Failure audit events record `outcome: inspection_failed`; audit writes remain best-effort.

If output inspection fails after SSE headers were sent, LSDF emits one terminal error event, withholds pending content, and does not send a successful `[DONE]`. Previously delivered text cannot be withdrawn. Upstream transport failures remain a separate 502 or terminal SSE `upstream_transport_error`.

Use an ASCII management token. Malformed non-ASCII credentials are rejected with 401; management credentials do not authenticate chat-completion clients.

## Audit Operations

Durable audit JSONL remains best-effort and fail-open. A shared sink serializes rotation and appends from gateway threads. Use one writer process per audit path; multiple processes, separate sink instances, and external rotation or purge require coordination. Rotation is configured with:

```bash
LSDF_AUDIT_ROTATE_BYTES=10485760 \
LSDF_AUDIT_ROTATE_BACKUPS=5 \
  docker compose --env-file .lsdf.env up -d gateway
```

Export safe audit fields:

```bash
docker compose run --rm cli audit-summary .lsdf/audit.jsonl
docker compose run --rm cli audit-export .lsdf/audit.jsonl --target splunk
```

## Encrypted Token Vault

Generate a vault key:

```bash
docker compose run --rm cli vault keygen
```

Store the generated key securely and supply it as `LSDF_VAULT_KEY` in the host environment. Configure reversible tokenization with `LSDF_TOKENIZATION_MODE=vault` and `LSDF_VAULT_PATH=/workspace/.lsdf/vault.sqlite`, then recreate the gateway with the same settings. Use separate host environment variables `LSDF_OLD_VAULT_KEY` and `LSDF_NEW_VAULT_KEY` for rotation. The source `cli` service does not inherit these shell variables automatically; pass each required key with `run -e`. The following commands operate on the source-checkout vault:

```bash
docker compose run --rm cli vault status --vault-path .lsdf/vault.sqlite
docker compose run --rm cli vault check --vault-path .lsdf/vault.sqlite
docker compose run --rm cli vault backup --vault-path .lsdf/vault.sqlite --output .lsdf/vault.backup.sqlite
docker compose run --rm -e LSDF_OLD_VAULT_KEY -e LSDF_NEW_VAULT_KEY cli vault rotate-key --vault-path .lsdf/vault.sqlite --old-key-env LSDF_OLD_VAULT_KEY --new-key-env LSDF_NEW_VAULT_KEY --output .lsdf/vault.rotated.sqlite
docker compose run --rm -e LSDF_VAULT_KEY cli vault resolve TOKEN_FROM_YOUR_VAULT --vault-path .lsdf/vault.sqlite
```

Vault backups use SQLite's online backup API, including committed WAL transactions. Choose a new output filename in a trusted directory: backup and rotation reject existing outputs, source aliases, symlinks, and existing SQLite sidecars, and reserve the new file with owner-only permissions. Keep its parent directory protected from other writers. Keep writers coordinated during key rotation; a backup is a consistent point-in-time copy, not a continuously updated replica.

Printing plaintext requires `--reveal-sensitive-value`.

`rotate-key` writes a new vault file and never mutates the source vault in place. Keep vault backups and keys together only in secured storage; losing the vault key means LSDF cannot recover plaintext token values.

## Proof Bundle

Create a raw-value-safe review bundle for security-team evaluation after generating audit and metrics files. Select the profile and any domain packs to match the policy being reviewed; this example reviews `default`:

```bash
docker compose run --rm cli proof-bundle --profile default --output .lsdf/proof --audit-jsonl-path .lsdf/audit.jsonl --metrics-jsonl-path .lsdf/metrics.jsonl --format markdown
```

The bundle includes policy summary, detector provenance, protection-report totals, known-gap counts, audit schema/summary, metrics summary, management posture, vault posture, and explicit non-certification language.
