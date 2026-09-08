# LSDF Latency Suite

_Generated 2026-05-07T05:01:26Z._

**Historical snapshot; presentation corrected 2026-09-08.** No benchmark was rerun for this edit. Every recorded payload latency and streaming measurement is preserved. Each payload's six identical statistics are collapsed to its single measured value; the derived single-call reciprocal is omitted because it does not establish throughput capacity. [Current report generation](#reproduce) writes ignored scratch files.

Per-profile, per-payload latency. CPU-only — dependency-light profiles (default/balanced) use regex, entropy, medical patterns, and contextual-anchored detection; the optional `broad-pii-ml` profile loads the OpenAI privacy-filter transformer model on CPU. GPU paths for the optional adapter are out of scope for this artifact and tracked separately.

## Payload matrix

| Name | Bytes | Description |
| --- | ---: | --- |
| `small_chat_turn` | 172 | Single chat-style user turn (~0.4 KB). |
| `medium_with_rag` | 706 | Chat turn plus two short RAG chunks (~2 KB). |
| `large_assistant_reply` | 14,720 | Long assistant output content (~16 KB). |
| `rag_heavy_session` | 32,519 | Multi-turn conversation with three large RAG chunks (~32 KB). |

Each payload below is one recorded `Firewall.inspect` sample (`iterations=1`), not a percentile distribution. No warmup samples were discarded. Streaming tables retain their actual repeated chunk counts.

## Profile `default`

Detector families: regex, entropy, medical-regex, contextual-anchored. Mode: `redact`.

| Payload | Sample ms (n=1) |
| --- | ---: |
| `small_chat_turn` | 9.657 |
| `medium_with_rag` | 1.698 |
| `large_assistant_reply` | 20.459 |
| `rag_heavy_session` | 56.695 |

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

| Payload | Sample ms (n=1) |
| --- | ---: |
| `small_chat_turn` | 0.501 |
| `medium_with_rag` | 1.358 |
| `large_assistant_reply` | 18.853 |
| `rag_heavy_session` | 53.665 |

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

| Payload | Sample ms (n=1) |
| --- | ---: |
| `small_chat_turn` | 415.041 |
| `medium_with_rag` | 612.175 |
| `large_assistant_reply` | 8812.538 |
| `rag_heavy_session` | 16860.096 |

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

| Payload | Sample ms (n=1) |
| --- | ---: |
| `small_chat_turn` | 2304.033 |
| `medium_with_rag` | 3331.265 |
| `large_assistant_reply` | 14278.718 |
| `rag_heavy_session` | 26507.493 |

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

Generate current local reports while preserving this recorded snapshot. The [artifact script](../scripts/regenerate-artifacts.sh) atomically updates ignored `.lsdf/current-reports/` reports and keeps dependency-light and full-matrix results separate; foundation recall remains its canonical report/history writer.

```bash
bash scripts/regenerate-artifacts.sh
```

Dependency-light profiles only:

```bash
mkdir -p .lsdf/current-reports
docker compose run --rm cli latency-table --profile default --profile balanced --iterations 50 --format markdown > .lsdf/current-reports/performance-default-balanced.md.tmp && mv .lsdf/current-reports/performance-default-balanced.md.tmp .lsdf/current-reports/performance-default-balanced.md
```

Full matrix, with prepared optional dependencies and model cache:

```bash
mkdir -p .lsdf/current-reports
docker compose --profile optional run --rm optional-cli latency-table --profile default --profile balanced --profile broad-pii --profile broad-pii-ml --iterations 1 --format markdown > .lsdf/current-reports/performance-full-matrix.md.tmp && mv .lsdf/current-reports/performance-full-matrix.md.tmp .lsdf/current-reports/performance-full-matrix.md
```

The full-matrix example records one payload sample per profile. Increase `--iterations N` to measure a distribution; repeat `--profile NAME` for each intended profile. The [recorded EVAL latency](../EVAL.md#latency) uses a different representative payload and 50 iterations, so it is not interchangeable with these single-sample payload timings.

## Notes

- **Streaming-holdback latency** (governed by `LSDF_STREAM_HOLDBACK_CHARS`, default 512) is now characterised in the per-profile *Streaming per-chunk inspection* table above — `per-chunk p50` is the wall-clock cost of each `append()` against the holdback buffer; `end-to-end` is the full chunk-sequence cost including the final `check_pending()` flush. The holdback bytes themselves are constant per chunk; the scanner-cost variance is what the table captures.
- **GPU acceleration for the optional ML profile** is not yet characterized in this report. These are recorded CPU observations, not a deployment-capacity guarantee.
- **Measurement boundary:** Firewall construction/model loading was outside the payload timer. First-call initialization may still affect inspection latency. No warmup samples were discarded, so this snapshot does not establish steady-state behavior.
