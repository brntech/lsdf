# Provider Playbook

Updated: 2026-09-09

LSDF is provider-agnostic on the client side: applications point OpenAI-compatible clients at `http://localhost:8080/v1`, while LSDF forwards to the configured upstream.

Complete [Installation](installation.md) first. The commands below run from a source checkout. Start the real upstream separately and choose a model ID it serves; `init` only writes LSDF configuration. The v0.4.0 gateway implements `POST /v1/chat/completions`, including streaming, rather than the full OpenAI API.

## Presets

| Preset | Upstream URL | Best For |
| --- | --- | --- |
| `demo` | `http://demo-upstream:8091` | Deterministic quickstart and proof video capture. |
| `vllm` | `http://host.docker.internal:8000` | Local vLLM or another OpenAI-compatible server on the host. |
| `lmstudio` | `http://host.docker.internal:1234` | Native LM Studio OpenAI-compatible server. |
| `ollama` | `http://host.docker.internal:11434/v1` | Local Ollama OpenAI-compatible endpoint. |
| `litellm` | `http://host.docker.internal:4000` | LSDF in front of LiteLLM Proxy. |
| `openrouter` | `https://openrouter.ai/api/v1` | LSDF in front of OpenRouter. |
| `custom` | user supplied | Any OpenAI-compatible provider or gateway. |

## Commands

Choose one preset below. `--force` replaces an existing `.lsdf.env`; omit it when creating a new file or retain your existing settings when changing providers.

```bash
docker compose run --rm cli init --upstream demo --output .lsdf.env --force
docker compose run --rm cli init --upstream vllm --output .lsdf.env --force
docker compose run --rm cli init --upstream lmstudio --output .lsdf.env --force
docker compose run --rm cli init --upstream ollama --output .lsdf.env --force
docker compose run --rm cli init --upstream litellm --output .lsdf.env --force
docker compose run --rm cli init --upstream openrouter --output .lsdf.env --force
docker compose run --rm cli init --upstream custom --upstream-base-url https://provider.example/v1 --output .lsdf.env --force
docker compose --env-file .lsdf.env up gateway
```

For `demo`, also start the upstream with `docker compose up -d demo-upstream` before starting `gateway`. The other presets require a separately running upstream. Host-based providers must listen on an address reachable from Docker; a host-only loopback listener may not be reachable from a Linux container. The source Compose services include the Linux `host-gateway` mapping. Use a service name and its container port instead when the upstream shares LSDF's Compose network.

Supply `LSDF_UPSTREAM_API_KEY` through your shell or an uncommitted env file when the provider requires authentication. A client's bearer token is not forwarded upstream; LSDF uses the configured upstream key. `LSDF_MANAGEMENT_TOKEN` protects management endpoints and `LSDF_CLIENT_TOKEN` independently protects client chat requests. Shared deployments need separate ingress authentication and TLS.

An upstream URL may be its service root or a path prefix containing a `/v1` segment; LSDF avoids duplicating the incoming `/v1` route when forwarding. For example, the OpenRouter preset forwards chat to `/api/v1/chat/completions`, and the DeepInfra setup below forwards to `/v1/openai/chat/completions`.

Gateway policy precedence is explicit `--policy`, `LSDF_POLICY`, explicit `--profile`, `LSDF_PROFILE`, then `default`. Domain packs apply when selecting a profile, not an explicit policy file. Host shell variables override values supplied by Compose's `--env-file`; check existing `LSDF_POLICY` and `LSDF_PROFILE` settings when changing profiles. Other CLI commands should select their profile explicitly.

## Optional ML Gateway

The dependency-light `gateway` is the default. First follow [Optional ML installation](installation.md#optional-ml) to prepare both GLiNER and privacy-filter in the shared cache and verify the active detector families. Then run the optional gateway:

```bash
docker compose --profile optional build gateway-ml
docker compose run --rm cli policy-validate --profile broad-pii-ml
docker compose --profile optional run --rm optional-cli doctor --profile broad-pii-ml --format json
docker compose run --rm cli init --upstream vllm --profile broad-pii-ml --output .lsdf.env --force
docker compose --env-file .lsdf.env --profile optional up gateway-ml
```

`gateway-ml` and `gateway` both publish host loopback port 8080; run one at a time or remap ports. Application clients on the host still use `http://localhost:8080/v1`. Missing required GLiNER prevents startup. Privacy-filter is optional in `broad-pii-ml`: when it cannot load, the gateway can continue with the local broad-pii detector stack. A successful doctor exit alone does not prove privacy-filter loaded; check that its JSON detector-family list includes both `gliner` and `openai_privacy_filter`.

## OpenRouter

Use OpenRouter as the upstream:

```bash
docker compose run --rm cli init --upstream openrouter --output .lsdf.env --force
```

Application clients still call LSDF:

```text
http://localhost:8080/v1
```

LSDF does not forward arbitrary client headers, including OpenRouter app-attribution headers. If attribution is required, add it in an upstream proxy that sends requests to OpenRouter. Setting it only on the client that calls LSDF has no effect.

## DeepInfra

DeepInfra's OpenAI-compatible chat endpoint uses `https://api.deepinfra.com/v1/openai`. Use the v0.4.0 release image or a current source checkout and the `custom` upstream for this setup; it covers LSDF's `POST /v1/chat/completions` route only.

```bash
docker compose run --rm cli init --upstream custom --upstream-base-url https://api.deepinfra.com/v1/openai --output .lsdf.env --force
```

Set `LSDF_UPSTREAM_API_KEY` in the uncommitted `.lsdf.env`, then start the gateway:

```bash
docker compose --env-file .lsdf.env up --build -d gateway
```

Point an OpenAI-compatible client at `http://localhost:8080/v1` and choose a model available to your DeepInfra account. Keep the provider key in LSDF's upstream configuration; client requests use any configured `LSDF_CLIENT_TOKEN`.

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
