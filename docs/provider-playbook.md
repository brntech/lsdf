# Provider Playbook

Date: 2026-04-29

LSDF is provider-agnostic on the client side: applications point OpenAI-compatible clients at `http://localhost:8080/v1`, while LSDF forwards to the configured upstream.

## Presets

| Preset | Upstream URL | Best For |
| --- | --- | --- |
| `demo` | `http://demo-upstream:8091` | Deterministic quickstart and proof video capture. |
| `vllm` | `http://host.docker.internal:8000` | Local vLLM or another OpenAI-compatible server on the host. |
| `lmstudio` | `http://host.docker.internal:1234` | Native LM Studio OpenAI-compatible server. |
| `litellm` | `http://host.docker.internal:4000` | LSDF in front of LiteLLM Proxy. |
| `openrouter` | `https://openrouter.ai/api/v1` | LSDF in front of OpenRouter. |
| `custom` | user supplied | Any OpenAI-compatible provider or gateway. |

## Commands

```bash
docker compose run --rm cli init --upstream demo --output .lsdf.env --force
docker compose run --rm cli init --upstream vllm --output .lsdf.env --force
docker compose run --rm cli init --upstream lmstudio --output .lsdf.env --force
docker compose run --rm cli init --upstream litellm --output .lsdf.env --force
docker compose run --rm cli init --upstream openrouter --output .lsdf.env --force
docker compose run --rm cli init --upstream custom --upstream-base-url https://provider.example/v1 --output .lsdf.env --force
docker compose --env-file .lsdf.env up gateway
```

## Optional ML Gateway

The dependency-light `gateway` is the default. For OpenAI privacy-filter plus LSDF entropy/regex protection, run the optional ML gateway:

```bash
docker compose --profile optional build gateway-ml
docker compose run --rm cli policy-validate --profile broad-pii-ml
docker compose --profile optional run --rm optional-cli doctor --profile broad-pii-ml
LSDF_UPSTREAM_BASE_URL=http://host.docker.internal:8000 \
  docker compose --profile optional up gateway-ml
```

`gateway-ml` and `gateway` both bind `localhost:8080`; run one at a time or remap ports. Application clients still use `http://localhost:8080/v1`. The optional privacy-filter model must be present in the Docker cache, or the gateway will fail closed with a detector-unavailable diagnostic.

## OpenRouter

Use OpenRouter as the upstream:

```bash
docker compose run --rm cli init --upstream openrouter --output .lsdf.env --force
```

Application clients still call LSDF:

```text
http://localhost:8080/v1
```

OpenRouter supports optional app-attribution headers. Configure those in the application or upstream gateway layer if needed; LSDF does not rewrite provider attribution headers in this pass.

## LiteLLM Proxy

Recommended topology:

```text
app -> LSDF gateway -> LiteLLM Proxy -> provider fleet
```

Advanced topology:

```text
app -> LiteLLM Proxy -> LSDF gateway -> single upstream
```

The advanced topology can be useful when LiteLLM must remain application-facing, but LiteLLM auth, routing, and logging may see data before LSDF unless that deployment is configured carefully.

Run the dependency-free proxy-shaped topology smoke. The runner sends a streaming request through LSDF and the proxy-shaped hop:

```bash
docker compose --profile litellm-demo up --build --abort-on-container-exit --exit-code-from litellm-demo-runner litellm-demo-runner
docker compose --profile litellm-demo down
```

This validates LSDF in front of an OpenAI-compatible proxy hop without adding LiteLLM as an LSDF runtime dependency.

## Compatibility Checklist

- Supports `POST /v1/chat/completions`.
- Supports OpenAI-compatible streaming SSE when `stream=true`.
- Preserves `choices[].delta.content` and tool-call deltas.
- Accepts bearer auth or no auth as configured.
- Uses model IDs compatible with your application.
- Handles upstream transport failures cleanly.
- Places observability logs after LSDF when sensitive payloads should be sanitized first.
