# Compatibility Matrix

Updated: 2026-09-08

Use Docker Compose for LSDF verification, for example `docker compose run --rm cli doctor`. See [Installation](installation.md) for prerequisites, source downloads, and the prebuilt-image path.

| Surface | Status | Notes |
| --- | --- | --- |
| Standalone gateway image | Supported Docker path | `runtime` starts the gateway without a source mount; `runtime-optional` adds explicit heavy dependencies and requires model readiness checks. |
| Release image architecture | `linux/amd64` | The released image builds and checks cover this platform only. Native ARM64 release images are unverified. This is a container-platform statement, not a host-OS support matrix. |
| OpenAI-compatible chat completions | Supported | `/v1/chat/completions` proxy path. |
| Non-streaming responses | Supported | Request preflight plus response inspection. |
| Streaming content/reasoning | Supported | Rolling holdback inspection. SDK timing notes and per-chunk metric reference: `streaming-compatibility.md`. |
| Streamed tool-call arguments | Supported | Arguments are assembled before release. |
| Observability traces/logs/spans | Supported | Shape-based `logs.traces` sanitizer. |
| LM Studio | Supported by recipe | Use `http://host.docker.internal:1234`. |
| local vLLM | Supported by recipe | Use `http://host.docker.internal:8000`. |
| LiteLLM Proxy | Supported by preset/recipe | Use `docker compose run --rm cli init --upstream litellm`; recommended topology is app -> LSDF -> LiteLLM. |
| OpenRouter | Supported by preset/recipe | Use `docker compose run --rm cli init --upstream openrouter`; LSDF forwards to `https://openrouter.ai/api/v1`. |
| LangChain/LlamaIndex/LiteLLM | Runnable shape proof | Dependency-free runner exercises equivalent OpenAI-compatible request shapes; SDK-native helpers are not shipped. |
| SIEM export | Basic | Generic/Splunk/Elastic/Datadog-safe JSONL shapes. |
| Reversible tokenization | Supported | Encrypted local SQLite vault. |
| Vault backup/check/rotation | Supported | Local SQLite/Fernet vault only; external KMS is not implemented. |
| Management endpoint auth | Supported | Optional `LSDF_MANAGEMENT_TOKEN`; `/v1/*` is unaffected. |
| Client authentication | External control required | LSDF does not authenticate `/v1/chat/completions` callers. Use a trusted network or an authenticating reverse proxy; management tokens and upstream provider keys do not provide LSDF client authentication. |
| Policy signing | Supported | Ed25519 signatures; legacy hash sidecars remain readable. |
| Golden demo/proof bundle | Supported | Docker Compose demo profile plus `docker compose run --rm cli proof-bundle`. |
| Optional ML gateway | Supported by optional profile | `gateway-ml` uses `broad-pii-ml`, OpenAI privacy-filter, entropy, and Docker-managed model cache. |
| Custom ML detectors | Library extension point | User-supplied detectors can plug into the registry for application code and tests; gateway runtime plugin loading is not implemented. |
| Demo media kit | Captured transcript and terminal playback | [Captured demo output](../examples/demo-media/golden-demo.captured.txt) and an [asciinema cast](../examples/demo-media/golden-demo.cast) ship alongside the narration script. A GIF/video asset is not included. |
