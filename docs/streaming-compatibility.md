# Streaming Compatibility Notes

LSDF intercepts SSE-streamed `chat.completions` responses on the way back
from the upstream provider, holds back a rolling window of pending text
long enough to run the full detector chain on each chunk, then releases
the inspected portion downstream. That holdback is what makes streaming
inspection work — but it also changes the timing characteristics of the
SSE stream as seen by client SDKs that expect exact OpenAI event timing.

This doc covers the four things SDK integrators need to know:

- The holdback window and how to tune it.
- Per-chunk inspection latency and how to observe it.
- SDK-specific compatibility gotchas (openai-python, langchain,
  llamaindex, fetch / Server-Sent-Events readers).
- When to disable streaming entirely.

## 1. The rolling holdback window

When LSDF inspects a streaming response, it accumulates a rolling
buffer of unreleased characters per content/reasoning surface. Once the
buffer exceeds the configured holdback length, the leading prefix is
inspected in full, transformed if a finding fires, and emitted. The
trailing characters (up to the holdback length) stay in the buffer for
the next chunk's inspection pass — this is what catches a credential
shape that happens to straddle a chunk boundary.

| Setting | Default | Range |
|---|---|---|
| `LSDF_STREAM_HOLDBACK_CHARS` | `512` | non-negative integer |

Operational guidance:

- **Lower values reduce time-to-first-token** but make boundary-straddling
  detections more dependent on the upstream provider's chunk size. If
  the provider emits one-character SSE deltas (rare but possible), a
  `0`-byte holdback inspects each character independently — fine for
  PERSON / EMAIL shapes but unreliable for long credential prefixes
  like AWS session tokens (~100+ chars).
- **Higher values catch longer shapes reliably** but delay the visible
  start of the response by `<holdback_chars>` characters. At a typical
  60 tokens/sec output rate, 512 chars ≈ 100 tokens ≈ 1.6 s holdback.
- **`0` disables holdback entirely**; LSDF inspects each chunk in
  isolation. Acceptable when the upstream is known to emit large chunks
  or the surface is unlikely to host straddling shapes (reasoning,
  tool-call arguments).
- **The holdback is per-surface**, not global — distinct content,
  reasoning, and stream_chunk surfaces each carry their own buffer.

The terminal SSE chunk (`[DONE]`) flushes whatever remains in the
buffer through one final inspection pass, so the released payload is
always complete and inspected.

## 2. Per-chunk inspection latency

Two duration metrics report the inspection cost per chunk:

| Metric | Labels | When it fires |
|---|---|---|
| `stream_chunk_inspection_ms` | `stream`, `surface` | Per arriving content / reasoning delta that triggers a holdback-window inspection (`StreamingInspectionState.append`), plus one additional observation per surface at the terminal flush (`check_pending` during `[DONE]`). |
| `stream_metadata_inspection_ms` | `stream` | One envelope preflight per parsed SSE event and one separate metadata preflight per parsed JSON payload. No envelope is scanned twice for the same event. |
| `stream_tool_call_inspection_ms` | `stream` | At the terminal flush of streaming tool-call argument fragments, once per tool-call surface. The append-side call into `StreamingToolCallArgumentState` does not inspect; argument fragments are reassembled and inspected in full at flush time. |

The aggregate `response_inspection_ms` metric continues to fire only on
the non-SSE fallback path (full-response inspection).

Per-chunk inspection cost varies by detector set, hardware, and chunk
size. Default-profile measurements are now captured in
`docs/performance.md` § "Streaming per-chunk inspection" (regenerated
each release via `bash scripts/regenerate-artifacts.sh`); the
representative numbers operators should plan against on commodity x86
CPUs with the default profile (regex + entropy + medical-regex +
contextual-anchored, no optional ML model):

| Stream shape | Chunks | per-chunk p50 | p95 | end-to-end p50 |
|---|---:|---:|---:|---:|
| 22 deltas of ~8 chars (typical chat reply, all chunks held in the buffer until flush) | 22 | ~0.1 ms | ~0.2 ms | ~2.4 ms |
| 127 deltas of ~12 chars (long assistant turn — buffer cycles through the holdback multiple times) | 127 | ~0.5 ms | ~0.7 ms | ~60 ms |
| 40 deltas spanning ~700 chars of audit prose so a Stripe-key shape lands AFTER the holdback first releases — exercises the cross-boundary detection path | 40 | ~0.3 ms | ~0.5 ms | ~12 ms |

These are the committed-artifact numbers; refresh from `docs/performance.md`
for the latest measurement. Under the optional `broad-pii-ml` profile
the transformer model runs on each holdback window — typically
two-to-three orders of magnitude slower per chunk than the default
profile. The streaming benchmark is not run for `broad-pii-ml` in the
release-artifact regen path (the wall-clock cost compounds across
chunks × iterations). Operators should take readings from their own
deployment via the bundled Grafana dashboard panel 10 (`stream_chunk_inspection_ms`
p50/p95/max grouped by surface) before sizing holdback budgets for
`broad-pii-ml`. Tune `LSDF_STREAM_HOLDBACK_CHARS` higher in `broad-pii-ml`
so the model amortises across larger inspection batches.

## 3. SDK compatibility checklist

LSDF's gateway is OpenAI-compatible and emits standard SSE shape: each
event is a `data: ` prefixed JSON line, terminated by a `data: [DONE]`
line. The visible-to-client differences from a direct upstream are:

1. **Time-to-first-token** is delayed by approximately
   `holdback_chars / output_chars_per_second` seconds.
2. **Per-event payloads may be coalesced or split** vs the upstream's
   exact deltas — LSDF re-chunks based on its inspection pass and
   transformation needs. The total reassembled content is identical;
   the per-chunk byte boundaries are not.
3. **A finding-triggered transform** can replace text inside a delta
   that the upstream did not modify. Clients that hash or memoise
   per-event content should hash the reassembled response, not the raw
   chunks.

### openai-python

The standard `client.chat.completions.create(..., stream=True)`
iterator works without modification. Each iteration yields a
`ChatCompletionChunk` whose `choices[0].delta.content` may be a coalesced
slice from a longer underlying delta. No change required at the SDK
level; the integration shape is identical to talking to OpenAI directly.

If your application relies on `chunk.choices[0].finish_reason` to detect
the end of a stream, note that LSDF emits the same `finish_reason`
LSDF received from the upstream. The SDK-level done-detection code is
unaffected.

### LangChain (Python)

Both `ChatOpenAI(streaming=True)` and the new `init_chat_model`
streaming paths consume the standard SSE shape and work without
modification. If a `StreamingStdOutCallbackHandler` is hooked in,
expect the visible "first token" delay described above; the total
response stream is unchanged. `BaseChatModel.astream` and
`AsyncCallbackManagerForLLMRun.on_llm_new_token` carry the LSDF-
inspected text, not the raw upstream delta.

### LlamaIndex

`OpenAI(model=..., streaming=True)` and the chat-engine streaming wrapper
consume LSDF-inspected SSE without modification. The `delta` field on
each chunk reflects LSDF's re-chunking; `response.message.content`
reassembles the full inspected text.

### CrewAI / Haystack

Both wrap `openai-python`'s streaming; no extra work required.

### Browser fetch + ReadableStream

If you read the SSE stream directly via `fetch(..., {body, headers})`
and a `getReader()` loop, the `data: <json>\n\n` framing is unchanged.
TextDecoder must handle UTF-8 multi-byte sequences split across chunk
boundaries — same as talking to OpenAI directly. LSDF respects UTF-8
character boundaries when inspecting; it never splits a multi-byte
character mid-sequence.

### Server-Sent Events (Node, Deno, EventSource API)

The v0.4.1 gateway inspects recognized text/reasoning fields and assembled tool-call arguments, plus surrounding JSON metadata and SSE envelope values. Metadata is inspected before caching or emission, including on empty-data and `[DONE]` events. Unknown extensions include both scalar values and unknown key names. An enforcing metadata decision emits a safe terminal error and withholds pending content; metadata is preserved only when the policy permits it and is never rewritten. See the [security model](security-model.md#detector-posture) for policy classification and narrow entropy-only identifier rules.

If a streaming request receives a non-SSE JSON object response, LSDF applies the same JSON metadata rejection and normal content transformation rules. These controls are included in v0.4.1.

The SSE `id:` field may vary between events and is copied from the inspected upstream envelope when present. The JSON payload `id` must remain unchanged after its first appearance; a conflicting or non-string ID terminates the stream before that frame is emitted. Omitted IDs remain allowed. Flush chunks preserve inspected fields from their prior templates, while synthetic/error chunks can omit identifiers. LSDF does not invent IDs.

A tool call's nonempty ID and function name must each arrive once as a complete value. Later nonempty occurrences, including identical repeats or duplicate semantic indexes within one frame, terminate the stream because some clients concatenate them. Empty, null, or omitted continuations are allowed; other non-string identity values are rejected. Argument fragments are assembled before inspection, including their JSON object keys. This supports the bounded initial-identity/continued-arguments shape, not arbitrary fragmented tool identities.

## 4. When to disable streaming

Streaming inspection has a fundamental tradeoff: the inspection window
is bounded by what has arrived so far. A hostile prompt that
intentionally interleaves credential prefixes across many small chunks
is harder to detect than the same payload in a single non-streamed
response.

Three rules of thumb:

- **High-risk surfaces (tool-call arguments) should not stream.** The
  bundled gateway already enforces full-buffer reassembly for
  tool-call argument fragments, but if your upstream forces SSE-only
  emission of tool calls, prefer non-streaming for those routes.
- **Low-latency UX vs strict containment.** If the application is a
  developer chat-style UI where time-to-first-token matters and the
  acceptable risk profile excludes credential-leak shapes, lower
  `LSDF_STREAM_HOLDBACK_CHARS` to 64-128. If the application is an
  agent loop where the streamed text feeds into a tool dispatcher,
  prefer the default 512 or higher.
- **For the optional `broad-pii-ml` profile**, the per-chunk model
  inference cost makes streaming inspection ~30-100× slower than the
  default profile per chunk. Either accept the latency or run
  non-streaming for surfaces requiring ML detection.

## 5. Reference

| Env var | Default | Notes |
|---|---|---|
| `LSDF_STREAM_HOLDBACK_CHARS` | `512` | Set to `0` to inspect each chunk in isolation; raise above 512 if the upstream emits large chunks and you want fewer inspections per response. |

To opt out of streaming inspection entirely, configure the application
to issue non-streaming requests (`stream: false`). LSDF does not expose
a per-route bypass; the holdback budget is the right knob for tuning
streaming UX while keeping inspection on.

The bundled `examples/quickstart/stream_redact_request.json` payload
exercises the streaming path end-to-end:

```bash
curl http://localhost:8080/v1/chat/completions \
    -H "Content-Type: application/json" \
    -d @examples/quickstart/stream_redact_request.json
```

Compare the visible time-to-first-token against a direct upstream
request to quantify the holdback budget you have available.

## Terminal errors and response headers

An output inspection failure after SSE headers have been sent terminates the stream with a raw-value-safe error event. Already delivered text cannot be withdrawn. The initial `x-lsdf-blocked` and `x-lsdf-decision-count` headers precede output inspection and are not a final decision summary; inspect terminal events and audit output. Final text can share a chunk with its finish reason and is emitted in text order after terminal checks.
