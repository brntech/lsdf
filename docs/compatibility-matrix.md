# Compatibility Matrix

Updated: 2026-09-08

Use Docker Compose for LSDF verification, for example `docker compose run --rm cli doctor`. See [Installation](installation.md) for prerequisites, source downloads, and the prebuilt-image path.

| Surface | Status | Notes |
| --- | --- | --- |
| Standalone gateway image | Supported Docker path | `runtime` starts the gateway without a source mount; `runtime-optional` adds explicit heavy dependencies and requires model readiness checks. |
| Release image architecture | `linux/amd64` | The released image builds and checks cover this platform only. Native ARM64 release images are unverified. This is a container-platform statement, not a host-OS support matrix. |
| OpenAI-compatible chat completions | Supported | `/v1/chat/completions` proxy path. |
| Non-streaming responses | Supported in current source | Request preflight, content transforms, and metadata inspection without identity rewriting. Unsupported non-SSE response bodies are withheld with HTTP 502. See [metadata coverage](security-model.md). |
| Streaming response metadata | Inspected in current source | JSON metadata and SSE envelope values are preflighted. Unsafe metadata withholds pending content. JSON IDs must remain stable; tool IDs/names must arrive as complete initial values. See [streaming compatibility](streaming-compatibility.md#server-sent-events-node-deno-eventsource-api). |
| Streaming content/reasoning | Supported | Rolling holdback inspection; final deltas preserve text order, including a delta carrying its finish reason. SDK timing notes and per-chunk metric reference: `streaming-compatibility.md`. |
| Streamed tool-call arguments | Supported | Arguments are assembled before release. Current source scans parsed JSON keys and values; enforcing key findings withhold the payload without renaming keys. The v0.3.2 image predates key inspection and metadata enforcement. |
| Observability traces/logs/spans | Supported | Shape-based `logs.traces` sanitizer. |
| LM Studio | Supported by recipe | Use `http://host.docker.internal:1234`. |
| local vLLM | Supported by recipe | Use `http://host.docker.internal:8000`. |
| Ollama OpenAI-compatible endpoint | Supported by preset/recipe | Use `docker compose run --rm cli init --upstream ollama`; the source gateway uses `http://host.docker.internal:11434/v1`. |
| LiteLLM Proxy | Supported by preset/recipe | Use `docker compose run --rm cli init --upstream litellm`; recommended topology is app -> LSDF -> LiteLLM. |
| OpenRouter | Supported by preset/recipe | Use `docker compose run --rm cli init --upstream openrouter`; LSDF forwards to `https://openrouter.ai/api/v1`. |
| LangChain/LlamaIndex/LiteLLM | Runnable shape proof | Dependency-free runner exercises equivalent OpenAI-compatible request shapes; SDK-native helpers are not shipped. |
| SIEM export | Basic | Generic/Splunk/Elastic/Datadog-safe JSONL shapes. |
| Reversible tokenization | Supported | Encrypted local SQLite vault. |
| Vault backup/check/rotation | Supported | Consistent SQLite online backups, including WAL, to a new output file; external KMS is not implemented. |
| Management endpoint auth | Supported | Optional `LSDF_MANAGEMENT_TOKEN`; `/v1/*` is unaffected. |
| Client authentication | Supported in current source/runtime | Set `LSDF_CLIENT_TOKEN` independently from `LSDF_MANAGEMENT_TOKEN`; the v0.3.2 published image predates this control, so use a current image before relying on it. |
| Request and stream limits | Supported in current source/runtime | `LSDF_MAX_REQUEST_BYTES`, `LSDF_MAX_CONCURRENT_REQUESTS`, client/upstream timeouts, maximum stream duration, and stream holdback are reported by authenticated health; no sustained-load certification is implied. |
| Policy signing | Supported | Ed25519 required for enforced custom policies; legacy hash sidecars are CLI migration artifacts only. |
| Golden demo/proof bundle | Supported | Docker Compose demo profile plus `docker compose run --rm cli proof-bundle`. |
| Optional ML gateway | Supported by optional profile | `gateway-ml` uses `broad-pii-ml`, OpenAI privacy-filter, entropy, and Docker-managed model cache. |
| Custom ML detectors | Library extension point | User-supplied detectors can plug into the registry for application code and tests; gateway runtime plugin loading is not implemented. |
| Demo media kit | Captured transcript and terminal playback | [Captured demo output](../examples/demo-media/golden-demo.captured.txt) and an [asciinema cast](../examples/demo-media/golden-demo.cast) ship alongside the narration script. A GIF/video asset is not included. |
