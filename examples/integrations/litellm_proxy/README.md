# LSDF With LiteLLM Proxy

Recommended topology:

```text
app -> LSDF gateway -> LiteLLM Proxy -> provider fleet
```

This keeps request preflight, streaming holdback, tool-call argument inspection, audit, and metrics in front of the model-routing layer.

Start LSDF with the LiteLLM preset:

```bash
docker compose run --rm cli init --upstream litellm --output .lsdf.env --force
docker compose --env-file .lsdf.env up gateway
```

Run a dependency-free topology smoke that inserts an OpenAI-compatible proxy-shaped service between LSDF and the demo upstream. The runner sends a streaming request through the topology:

```bash
docker compose --profile litellm-demo up --build --abort-on-container-exit --exit-code-from litellm-demo-runner litellm-demo-runner
docker compose --profile litellm-demo down
```

This smoke does not install LiteLLM. It validates the LSDF-side topology and URL semantics while keeping real LiteLLM deployment as an external runtime.

Point application clients at LSDF:

```text
http://localhost:8080/v1
```

Advanced topology:

```text
app -> LiteLLM Proxy -> LSDF gateway -> single upstream
```

Use this only when LiteLLM must stay application-facing. In that topology, LiteLLM routing, auth, and logging may see payloads before LSDF unless the LiteLLM deployment is configured to avoid pre-LSDF persistence.
