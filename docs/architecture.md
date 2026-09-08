# Architecture

## High-level architecture

```text
Client application / agent
        ↓
LLM Sensitive Data Firewall
        ↓
Provider router / local model gateway
        ↓
LLM provider or self-hosted model
```

## Runtime flow

```text
1. Receive request
2. Parse messages, tools, metadata, and RAG context
3. Scan input surfaces
4. Apply configured policy decisions and transformations
5. Forward transformed request to model
6. Stream or receive model output
7. Scan output content and structured fields
8. Inspect model-returned tool-call arguments before client release
9. Emit audit event
10. Return safe response or policy decision
```

## Surfaces

- `input.messages`
- `input.system`
- `input.developer`
- `input.rag_context`
- `input.tool_results`
- `output.content`
- `output.stream_chunk`
- `output.tool_calls.arguments`
- `output.reasoning`
- `logs.traces`

Transcript-like payloads are handled through `logs.traces`. A distinct `storage.transcripts` surface is not implemented. The gateway inspects supported model traffic. Trace/log sanitation is a separate library or CLI call that the application wires before observability ingestion; it is not a step performed automatically by the gateway. Actual tool execution also requires application wiring.

## Deployment modes

- Local proxy
- Self-hosted gateway
- Sidecar
- Library/SDK
