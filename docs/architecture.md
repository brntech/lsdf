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
4. Apply policy actions: allow, warn, log, redact, mask, tokenize, block
5. Forward transformed request to model
6. Stream or receive model output
7. Scan output content and structured fields
8. Scan tool calls before execution
9. Sanitize traces/logs
10. Emit audit event
11. Return safe response or policy decision
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

Transcript-like payloads are currently handled through `logs.traces`. A distinct `storage.transcripts` surface is not implemented.

## Deployment modes

- Local proxy
- Self-hosted gateway
- Sidecar
- Library/SDK
