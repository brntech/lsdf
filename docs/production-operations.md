# Production Operations

Date: 2026-04-29

Provider rollout material covers LiteLLM Proxy, OpenRouter, LM Studio, local vLLM, and generic OpenAI-compatible upstreams. Use `docs/provider-playbook.md` for topology choices, and keep the recommended LiteLLM flow as `app -> LSDF gateway -> LiteLLM Proxy -> provider fleet`.

LSDF now exposes raw-value-safe operational surfaces while keeping OpenAI-compatible `/v1/*` behavior unchanged.

## Standalone Runtime Image

The lightweight `runtime` target starts the gateway on port 8080. It includes LSDF source, policies, required synthetic policy-validation fixtures, and three first-party proof matrices. It does not include development test code, external benchmark corpora, model weights, or heavy detector dependencies. The existing `base` and `optional-detectors` targets support repository development and evaluation.

Build and run from a source checkout without mounting that checkout into the gateway:

```bash
LSDF_UPSTREAM_BASE_URL=http://host.docker.internal:8000 \
  docker compose --profile runtime up --build runtime
```

Point clients at `http://localhost:8080/v1`. This local recipe binds the host port to loopback. The service forwards the same gateway settings as the development gateway. Its named volume persists `/workspace/.lsdf` for configured audit, metrics, proof, and encrypted vault files; use paths inside that directory. Custom policy files need an explicit read-only mount and policy argument. For a real upstream, supply `LSDF_UPSTREAM_API_KEY` through the environment when required. For shared access, configure `LSDF_MANAGEMENT_TOKEN` or disable management endpoints; apply the network and authentication controls below.

The image accepts CLI arguments, for example `docker compose --profile runtime run --rm runtime doctor`. Proof commands work in the runtime, but persist generated reports with an explicit output volume. Full benchmark evaluation and the live demo runner use the development Compose services and source checkout. A standalone Python wheel is not the supported distribution path: policy assets currently depend on the container's repository layout.

For v0.3.1 (unreleased), the release workflow is configured to publish `ghcr.io/brntech/lsdf:vX.Y.Z` and `:vX.Y.Z-optional`. Pin a verified digest for deployment. Both runtime images start with the dependency-light `default` profile. Select `LSDF_PROFILE=broad-pii-ml` explicitly only after mounting and preparing the model cache and checking `doctor --profile broad-pii-ml`. The `runtime-optional` target contains heavier dependencies and the spaCy language model; GLiNER and privacy-filter weights still require an explicit model-cache setup. Third-party licenses remain separate from LSDF's Apache-2.0 license; see `THIRD_PARTY_NOTICES.md`. An optional image build alone does not establish model readiness or recall.

## Optional ML Gateway

Use `gateway-ml` for the Docker-managed `broad-pii-ml` profile:

```bash
docker compose --profile optional build gateway-ml
docker compose run --rm cli policy-validate --profile broad-pii-ml
docker compose --profile optional run --rm optional-cli doctor --profile broad-pii-ml
LSDF_UPSTREAM_BASE_URL=http://host.docker.internal:8000 \
  docker compose --profile optional up gateway-ml
```

This path uses heavier optional dependencies and the `lsdf-hf-cache` Docker volume. Keep the default gateway for dependency-light local pilots. `broad-pii-ml` always includes the local broad-pii stack; OpenAI privacy-filter is an optional reference family that is used when loadable and skipped when unavailable. The optional image keeps GLiNER and OpenAI privacy-filter in separate Python dependency stacks so their incompatible Transformers requirements do not collide.

For release validation, regenerate the gate report:

```bash
docker compose --profile optional run --rm optional-cli eval-report --profile broad-pii --profile broad-pii-ml --format markdown
```

## Gateway Health And Metrics

Start the gateway with metrics enabled:

```bash
LSDF_METRICS_ENABLED=true \
LSDF_METRICS_JSONL_PATH=/workspace/.lsdf/metrics.jsonl \
LSDF_UPSTREAM_BASE_URL=http://host.docker.internal:8000 \
  docker compose up gateway
```

Check health and metrics:

```bash
curl http://localhost:8080/lsdf/health
curl http://localhost:8080/lsdf/metrics
curl "http://localhost:8080/lsdf/metrics?format=json"
docker compose run --rm cli metrics-summary .lsdf/metrics.jsonl --format markdown
docker compose run --rm cli smoke --gateway-base-url http://host.docker.internal:8080
docker compose run --rm cli quickstart-report --gateway-base-url http://host.docker.internal:8080 --audit-jsonl-path .lsdf/audit.jsonl --metrics-jsonl-path .lsdf/metrics.jsonl --format markdown
```

Metrics contain counts, durations, surfaces, entities, actions, detector families, stream states, status/error types, and no payload text.

Management endpoints are enabled by default for local compatibility. In shared environments, set `LSDF_MANAGEMENT_TOKEN` so `/lsdf/health` and `/lsdf/metrics` require `Authorization: Bearer <token>` or `X-LSDF-Management-Token`. Set `LSDF_MANAGEMENT_ENABLED=false` to disable `/lsdf/*` entirely; `/v1/*` remains unchanged.

## Audit Operations

Durable audit JSONL remains best-effort and fail-open. Rotation is configured with:

```bash
LSDF_AUDIT_JSONL_PATH=/workspace/.lsdf/audit.jsonl \
LSDF_AUDIT_ROTATE_BYTES=10485760 \
LSDF_AUDIT_ROTATE_BACKUPS=5 \
  docker compose up gateway
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

Configure reversible tokenization with `LSDF_TOKENIZATION_MODE=vault`, `LSDF_VAULT_PATH`, and `LSDF_VAULT_KEY`. Vault resolution is explicit:

```bash
docker compose run --rm cli vault status --vault-path .lsdf/vault.sqlite
docker compose run --rm cli vault check --vault-path .lsdf/vault.sqlite
docker compose run --rm cli vault backup --vault-path .lsdf/vault.sqlite --output .lsdf/vault.backup.sqlite
docker compose run --rm cli vault rotate-key --vault-path .lsdf/vault.sqlite --old-key-env LSDF_OLD_VAULT_KEY --new-key-env LSDF_NEW_VAULT_KEY --output .lsdf/vault.rotated.sqlite
docker compose run --rm cli vault resolve lsdf_tok_ssn_example --vault-path .lsdf/vault.sqlite
```

Printing plaintext requires `--reveal-sensitive-value`.

`rotate-key` writes a new vault file and never mutates the source vault in place. Keep vault backups and keys together only in secured storage; losing the vault key means LSDF cannot recover plaintext token values.

## Proof Bundle

Create a raw-value-safe review bundle for security-team evaluation:

```bash
docker compose run --rm cli proof-bundle --output .lsdf/proof --audit-jsonl-path .lsdf/audit.jsonl --metrics-jsonl-path .lsdf/metrics.jsonl --format markdown
```

The bundle includes policy summary, detector provenance, protection-report totals, known-gap counts, audit schema/summary, metrics summary, management posture, vault posture, and explicit non-certification language.
