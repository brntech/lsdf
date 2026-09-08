# LSDF Latency Suite

_Generated 2026-05-07T05:01:26Z._

Per-profile, per-payload latency. CPU-only — dependency-light profiles (default) run pure-Python regex/entropy/medical patterns; the optional `broad-pii-ml` profile loads the OpenAI privacy-filter transformer model on CPU. GPU paths for the optional adapter are out of scope for this artifact and tracked separately.

## Payload matrix

| Name | Bytes | Description |
| --- | ---: | --- |
| `small_chat_turn` | 172 | Single chat-style user turn (~0.4 KB). |
| `medium_with_rag` | 706 | Chat turn plus two short RAG chunks (~2 KB). |
| `large_assistant_reply` | 14,720 | Long assistant output content (~16 KB). |
| `rag_heavy_session` | 32,519 | Multi-turn conversation with three large RAG chunks (~32 KB). |

Each cell below is `iterations=1` of `Firewall.inspect`.

## Profile `default`

Detector families: regex, entropy, medical-regex, contextual-anchored. Mode: `redact`.

| Payload | Throughput/sec | min | p50 | p95 | p99 | max | avg |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `small_chat_turn` | 103.6 | 9.657 | 9.657 | 9.657 | 9.657 | 9.657 | 9.657 |
| `medium_with_rag` | 588.9 | 1.698 | 1.698 | 1.698 | 1.698 | 1.698 | 1.698 |
| `large_assistant_reply` | 48.9 | 20.459 | 20.459 | 20.459 | 20.459 | 20.459 | 20.459 |
| `rag_heavy_session` | 17.6 | 56.695 | 56.695 | 56.695 | 56.695 | 56.695 | 56.695 |

Latency is in milliseconds.

### Streaming per-chunk inspection

Per-chunk wall-clock cost of `StreamingInspectionState.append()` as the gateway feeds deltas through the holdback buffer (see `docs/streaming-compatibility.md`). End-to-end columns include the final `check_pending()` flush.

| Stream case | Chunks | Samples | per-chunk p50 | p95 | p99 | max | end-to-end p50 | p95 | max |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `short_assistant_stream` | 22 | 110 | 0.196 | 0.297 | 0.346 | 0.420 | 4.291 | 4.661 | 4.752 |
| `long_assistant_stream` | 127 | 635 | 0.843 | 0.982 | 1.407 | 1.853 | 96.285 | 98.057 | 98.058 |
| `leak_straddle_stream` | 40 | 200 | 0.573 | 0.915 | 1.209 | 1.322 | 20.658 | 28.647 | 30.477 |

Latency is in milliseconds.

## Profile `balanced`

Detector families: regex, entropy, medical-regex, contextual-anchored. Mode: `redact`.

| Payload | Throughput/sec | min | p50 | p95 | p99 | max | avg |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `small_chat_turn` | 1995.6 | 0.501 | 0.501 | 0.501 | 0.501 | 0.501 | 0.501 |
| `medium_with_rag` | 736.4 | 1.358 | 1.358 | 1.358 | 1.358 | 1.358 | 1.358 |
| `large_assistant_reply` | 53.0 | 18.853 | 18.853 | 18.853 | 18.853 | 18.853 | 18.853 |
| `rag_heavy_session` | 18.6 | 53.665 | 53.665 | 53.665 | 53.665 | 53.665 | 53.665 |

Latency is in milliseconds.

### Streaming per-chunk inspection

Per-chunk wall-clock cost of `StreamingInspectionState.append()` as the gateway feeds deltas through the holdback buffer (see `docs/streaming-compatibility.md`). End-to-end columns include the final `check_pending()` flush.

| Stream case | Chunks | Samples | per-chunk p50 | p95 | p99 | max | end-to-end p50 | p95 | max |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `short_assistant_stream` | 22 | 110 | 0.191 | 0.302 | 0.326 | 0.369 | 4.251 | 4.503 | 4.516 |
| `long_assistant_stream` | 127 | 635 | 0.841 | 0.971 | 1.408 | 2.336 | 95.762 | 98.720 | 99.136 |
| `leak_straddle_stream` | 40 | 200 | 0.486 | 0.845 | 1.296 | 1.318 | 20.573 | 23.276 | 23.842 |

Latency is in milliseconds.

## Profile `broad-pii`

Detector families: regex, entropy, medical-regex, contextual-anchored, contextual-broad, gliner. Mode: `redact`.

| Payload | Throughput/sec | min | p50 | p95 | p99 | max | avg |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `small_chat_turn` | 2.4 | 415.041 | 415.041 | 415.041 | 415.041 | 415.041 | 415.041 |
| `medium_with_rag` | 1.6 | 612.175 | 612.175 | 612.175 | 612.175 | 612.175 | 612.175 |
| `large_assistant_reply` | 0.1 | 8812.538 | 8812.538 | 8812.538 | 8812.538 | 8812.538 | 8812.538 |
| `rag_heavy_session` | 0.1 | 16860.096 | 16860.096 | 16860.096 | 16860.096 | 16860.096 | 16860.096 |

Latency is in milliseconds.

### Streaming per-chunk inspection

Per-chunk wall-clock cost of `StreamingInspectionState.append()` as the gateway feeds deltas through the holdback buffer (see `docs/streaming-compatibility.md`). End-to-end columns include the final `check_pending()` flush.

| Stream case | Chunks | Samples | per-chunk p50 | p95 | p99 | max | end-to-end p50 | p95 | max |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `short_assistant_stream` | 22 | 110 | 127.876 | 140.663 | 159.416 | 182.309 | 2951.702 | 3056.966 | 3075.756 |
| `long_assistant_stream` | 127 | 635 | 271.313 | 694.044 | 759.300 | 841.331 | 41138.812 | 41884.015 | 41978.221 |
| `leak_straddle_stream` | 40 | 200 | 160.752 | 201.159 | 206.714 | 230.290 | 6649.923 | 6716.368 | 6725.319 |

Latency is in milliseconds.

## Profile `broad-pii-ml`

Detector families: regex, entropy, medical-regex, contextual-anchored, contextual-broad, gliner, openai_privacy_filter. Mode: `redact`.

| Payload | Throughput/sec | min | p50 | p95 | p99 | max | avg |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `small_chat_turn` | 0.4 | 2304.033 | 2304.033 | 2304.033 | 2304.033 | 2304.033 | 2304.033 |
| `medium_with_rag` | 0.3 | 3331.265 | 3331.265 | 3331.265 | 3331.265 | 3331.265 | 3331.265 |
| `large_assistant_reply` | 0.1 | 14278.718 | 14278.718 | 14278.718 | 14278.718 | 14278.718 | 14278.718 |
| `rag_heavy_session` | 0.0 | 26507.493 | 26507.493 | 26507.493 | 26507.493 | 26507.493 | 26507.493 |

Latency is in milliseconds.

### Streaming per-chunk inspection

Per-chunk wall-clock cost of `StreamingInspectionState.append()` as the gateway feeds deltas through the holdback buffer (see `docs/streaming-compatibility.md`). End-to-end columns include the final `check_pending()` flush.

| Stream case | Chunks | Samples | per-chunk p50 | p95 | p99 | max | end-to-end p50 | p95 | max |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `short_assistant_stream` | 22 | 110 | 324.069 | 466.770 | 516.283 | 520.670 | 7563.548 | 7789.747 | 7844.453 |
| `long_assistant_stream` | 127 | 635 | 750.974 | 1247.252 | 1364.353 | 1730.747 | 98782.902 | 99277.516 | 99379.951 |
| `leak_straddle_stream` | 40 | 200 | 479.464 | 668.931 | 791.490 | 964.765 | 19451.926 | 20026.439 | 20054.330 |

Latency is in milliseconds.

## Reproduce

Dependency-light profiles only:

```bash
docker compose run --rm test python -m lsdf.cli latency-table --profile default --profile balanced --format markdown > docs/performance.md
```

Full release matrix, including optional ML profiles:

```bash
docker compose --profile optional run --rm optional-cli latency-table --format markdown 2>/dev/null > docs/performance.md
```

Override iterations or profiles with `--iterations N` and `--profile NAME` (repeat per profile).

## Notes

- **Streaming-holdback latency** (governed by `LSDF_STREAM_HOLDBACK_CHARS`, default 512) is now characterised in the per-profile *Streaming per-chunk inspection* table above — `per-chunk p50` is the wall-clock cost of each `append()` against the holdback buffer; `end-to-end` is the full chunk-sequence cost including the final `check_pending()` flush. The holdback bytes themselves are constant per chunk; the scanner-cost variance is what the table captures.
- **GPU acceleration for the optional ML profile** is not yet characterized in this report. The numbers above represent the CPU floor.
- **`broad-pii-ml` model load** (~1.4 B parameters) happens once at Firewall construction. Per-request latency above is steady-state after warmup; the suite discards no warmup samples (cold-start is visible in the `max` column for the first payload).
