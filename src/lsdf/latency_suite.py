# SPDX-License-Identifier: Apache-2.0
"""Latency benchmark suite.

Runs a fixed payload matrix (small chat turn → large RAG conversation) through
each requested profile, captures individual samples or repeated-run statistics,
and emits a report for an ignored local output path. Companion to
`release_eval.py` — that one captures detection quality, this one captures
inference cost so the two reports together describe the runtime.

Synthetic payloads are constructed in-process so the suite does not depend on
an external file matrix and so we can guarantee shape-faithful but
non-credential content. Each payload deliberately carries a few recognizable
shapes (Stripe key, JWT, email) so the scanner does the work it would in
production rather than walking benign strings.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .engine import Firewall
from .policy import load_effective_policy, load_policy_profile
from .streaming import DEFAULT_STREAM_HOLDBACK_CHARS, StreamingInspectionState


DEFAULT_PROFILES = ("default", "balanced", "broad-pii", "broad-pii-ml")
DEFAULT_ITERATIONS = 50


@dataclass(frozen=True)
class PayloadCase:
    name: str
    description: str
    payload: dict[str, Any]


@dataclass(frozen=True)
class StreamingCase:
    name: str
    description: str
    chunks: tuple[str, ...]


def build_streaming_matrix() -> list[StreamingCase]:
    """Three streaming chunk-sequence shapes spanning short -> long.

    Per-case `chunks` length is computed by slicing the underlying text;
    the actual count is in the `chunks_per_iteration` field of the
    benchmark JSON for downstream readers — the descriptions below
    name the shape, not the exact count.
    """
    short = tuple(_short_assistant_deltas())
    long_ = tuple(_long_assistant_deltas())
    straddle = tuple(_leak_straddle_deltas())
    return [
        StreamingCase(
            name="short_assistant_stream",
            description=f"{len(short)} 8-char deltas — typical chat reply.",
            chunks=short,
        ),
        StreamingCase(
            name="long_assistant_stream",
            description=f"{len(long_)} ~12-char deltas — long assistant turn.",
            chunks=long_,
        ),
        StreamingCase(
            name="leak_straddle_stream",
            description=(
                f"{len(straddle)} ~16-char deltas spanning ~700 chars of "
                f"prose so a Stripe-key shape arrives AFTER the "
                f"{DEFAULT_STREAM_HOLDBACK_CHARS}-char holdback first "
                "releases — exercises the cross-boundary detection path."
            ),
            chunks=straddle,
        ),
    ]


def _short_assistant_deltas() -> list[str]:
    base = (
        "I checked the configuration file and saw the issue. "
        "The Stripe key sk_live_LSDFFIXTUREaaaaaaaaaaaaaaaaaaaaaaaaaaa "
        "appears in line 8. Rotating immediately is recommended."
    )
    return [base[i : i + 8] for i in range(0, len(base), 8)]


def _long_assistant_deltas() -> list[str]:
    paragraph = (
        "Here is a longer assistant turn that walks through the audit. "
        "Findings include an exposed JWT eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9 "
        "in the staging response, an internal email at noreply@example.com "
        "in a webhook, and a phone number 555-867-5309 referenced in a draft. "
        "Each item should be classified, redacted on egress, and recorded in "
        "the audit trail per the policy. Recommended next steps: rotate the "
        "JWT, scrub the email from prior log lines, and confirm the phone is "
        "synthetic test data not customer PII. "
    ) * 3
    return [paragraph[i : i + 12] for i in range(0, len(paragraph), 12)]


def _leak_straddle_deltas() -> list[str]:
    # Build a chunk sequence long enough that the holdback buffer
    # actually releases mid-stream BEFORE the secret arrives. The
    # default holdback is 512 chars (`DEFAULT_STREAM_HOLDBACK_CHARS`).
    # We lay down ~700 chars of audit prose first, then the
    # Stripe-shape secret, so the scanner walks a fully-cycled buffer
    # when the secret crosses the boundary instead of accumulating
    # everything into one terminal flush.
    filler = (
        "Reviewing the recent audit pass for the production deployment. "
        "We walked through the staging configuration, the secrets-manager "
        "integration, and the per-environment overrides. Two findings "
        "from the prior pass are still open: a stale rotation policy on "
        "the database connection pool and an unreviewed change to the "
        "tracing pipeline that may surface request bodies in spans. "
        "Both are scheduled for remediation in the upcoming sprint. "
        "Continuing the review, the next item to flag is in the API "
        "configuration: "
    )
    secret_marker = "the Stripe key value is sk_live_"
    secret_tail = "LSDFFIXTUREaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    after = " appearing in production.yaml line 8. Recommend rotation."
    text = filler + secret_marker + secret_tail + after
    return [text[i : i + 16] for i in range(0, len(text), 16)]


def build_payload_matrix() -> list[PayloadCase]:
    """Four representative synthetic payloads spanning ~0.4 KB → ~32 KB."""
    return [
        PayloadCase(
            name="small_chat_turn",
            description="Single chat-style user turn (~0.4 KB).",
            payload={
                "messages": [
                    {
                        "role": "user",
                        "content": (
                            "Reset my Stripe key sk_live_LSDFFIXTUREaa"
                            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa "
                            "and email me at jane@example.org once done."
                        ),
                    }
                ]
            },
        ),
        PayloadCase(
            name="medium_with_rag",
            description="Chat turn plus two short RAG chunks (~2 KB).",
            payload={
                "messages": [
                    {
                        "role": "user",
                        "content": "Summarize the retrieved context and rotate any leaked tokens.",
                    }
                ],
                "rag_context": [
                    "Doc 1: deployment notes. Use service token Bearer "
                    "LSDFFIXTUREbearerAbCdEfGhIjKlMnOpQrStUvWxYz12 to validate "
                    "health checks, but rotate on each release. " * 2,
                    "Doc 2: an internal procedure. Patient takes metformin 500mg "
                    "and HbA1c 8.2% was noted. Contact admin@example.org for the "
                    "full chart export. " * 2,
                ],
            },
        ),
        PayloadCase(
            name="large_assistant_reply",
            description="Long assistant output content (~16 KB).",
            payload={
                "choices": [
                    {
                        "message": {
                            "content": (
                                "Step-by-step deployment guide. " * 80
                                + "Use AccountKey=LSDFFIXTUREaaaaaaaaaaaaaaaaaa"
                                "aaaaaaaaaaaaaaaaaaaaaaaaaaaa== for blob "
                                "storage and the SAS sv=2024-11-04&ss=bfqt&"
                                "srt=sco&sp=rwdlacupx&se=2026-01-01T00:00:00Z&"
                                "sig=LSDFFIXTUREsigaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa "
                                "for the audit container. " * 40
                                + "Final notes: contact alice@example.org "
                                "for credentials. " * 40
                            )
                        }
                    }
                ]
            },
        ),
        PayloadCase(
            name="rag_heavy_session",
            description="Multi-turn conversation with three large RAG chunks (~32 KB).",
            payload={
                "messages": [
                    {"role": "system", "content": "You are an internal helpdesk."},
                    {"role": "user", "content": "Audit the retrieved docs for leaked credentials."},
                    {
                        "role": "assistant",
                        "content": "I'll scan each chunk for tokens and PII.",
                    },
                    {"role": "user", "content": "Be thorough."},
                ],
                "rag_context": [
                    (
                        "Knowledge base entry. " * 200
                        + "Token: ghp_LSDFFIXTUREabcdefghijklmnopqrstuvwxyz1234567890. "
                        "Contact: ops@example.org. " * 100
                    ),
                    (
                        "Onboarding doc. " * 200
                        + "Use sk-ant-api03-LSDFFIXTURE"
                        + "a" * 80
                        + " for Anthropic and key-1234567890abcdef1234567890abcdef "
                        "for Mailgun. " * 80
                    ),
                    (
                        "Patient takes lisinopril 20mg per clinical history. "
                        * 200
                    ),
                ],
            },
        ),
    ]


def run_latency_suite(
    *,
    profiles: list[str] | tuple[str, ...] = DEFAULT_PROFILES,
    iterations: int = DEFAULT_ITERATIONS,
    streaming_iterations: int | None = None,
) -> dict[str, Any]:
    iterations = max(int(iterations), 1)
    cases = build_payload_matrix()
    streaming_cases = build_streaming_matrix()
    # Streaming benchmark dominates wall-clock when a chunk-rich case
    # runs many iterations against the broad-pii-ml profile (model
    # inspect cost × chunks × iterations). Default to a lower repeat
    # count unless caller overrides.
    if streaming_iterations is None:
        streaming_iterations = max(int(iterations) // 5, 5)
    profile_reports: list[dict[str, Any]] = []
    for profile_name in profiles:
        profile_reports.append(
            _measure_profile(
                profile_name,
                cases,
                streaming_cases,
                iterations=iterations,
                streaming_iterations=streaming_iterations,
            )
        )
    return {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "iterations_per_case": iterations,
        "streaming_iterations_per_case": streaming_iterations,
        "payloads": [
            {
                "name": case.name,
                "description": case.description,
                "size_bytes": _payload_bytes(case.payload),
            }
            for case in cases
        ],
        "streaming_cases": [
            {
                "name": case.name,
                "description": case.description,
                "chunk_count": len(case.chunks),
                "total_chars": sum(len(c) for c in case.chunks),
            }
            for case in streaming_cases
        ],
        "profiles": profile_reports,
    }


def _measure_profile(
    profile_name: str,
    cases: list[PayloadCase],
    streaming_cases: list[StreamingCase],
    *,
    iterations: int,
    streaming_iterations: int,
) -> dict[str, Any]:
    try:
        policy = load_policy_profile(profile_name)
    except Exception:
        try:
            policy = load_effective_policy(profile_name)
        except Exception as exc:
            return {
                "profile": profile_name,
                "available": False,
                "error": f"{type(exc).__name__}: {exc}",
            }
    try:
        firewall = Firewall(policy)
    except Exception as exc:
        return {
            "profile": profile_name,
            "available": False,
            "error": f"{type(exc).__name__}: {exc}",
        }
    case_results = []
    for case in cases:
        case_results.append(
            {
                "name": case.name,
                **_benchmark_payload(firewall, case.payload, iterations=iterations),
            }
        )
    streaming_results = []
    for case in streaming_cases:
        streaming_results.append(
            {
                "name": case.name,
                **_benchmark_streaming(
                    firewall, case.chunks, iterations=streaming_iterations
                ),
            }
        )
    return {
        "profile": profile_name,
        "available": True,
        "mode": policy.mode,
        "detector_families": firewall.detector_summary()["detector_families"],
        "cases": case_results,
        "streaming_cases": streaming_results,
    }


def _benchmark_streaming(
    firewall: Firewall, chunks: tuple[str, ...], *, iterations: int
) -> dict[str, Any]:
    """Drive the chunk sequence through StreamingInspectionState and
    record per-chunk inspection latency (the wall-clock cost of each
    `append()` call on the holdback-buffered surface)."""
    iterations = max(int(iterations), 1)
    per_chunk_ms: list[float] = []
    end_to_end_ms: list[float] = []
    for _ in range(iterations):
        state = StreamingInspectionState(
            firewall,
            surface_name="output.content",
            # The streaming state reuses the gateway's internal shadow
            # payload shape (`{"text": <accumulated buffer>}`); the
            # pointer must reach into that shadow envelope's `text`
            # leaf, not into a chat-completions wire envelope.
            pointer=("text",),
        )
        run_started = time.perf_counter()
        for chunk in chunks:
            t0 = time.perf_counter()
            state.append(chunk)
            per_chunk_ms.append((time.perf_counter() - t0) * 1000)
        # Final flush — same shape as the gateway's end-of-stream path.
        state.check_pending()
        end_to_end_ms.append((time.perf_counter() - run_started) * 1000)
    return {
        "iterations": iterations,
        "chunks_per_iteration": len(chunks),
        # iterations × chunks-per-iteration; surfaced so downstream
        # readers can reason about percentile stability.
        "per_chunk_sample_count": len(per_chunk_ms),
        "per_chunk_latency_ms": _summarize(per_chunk_ms),
        "end_to_end_latency_ms": _summarize(end_to_end_ms),
    }


def _summarize(values: list[float]) -> dict[str, float]:
    if not values:
        return {"min": 0.0, "p50": 0.0, "p95": 0.0, "p99": 0.0, "max": 0.0, "avg": 0.0}
    return {
        "min": min(values),
        "p50": _percentile(values, 50),
        "p95": _percentile(values, 95),
        "p99": _percentile(values, 99),
        "max": max(values),
        "avg": sum(values) / len(values),
    }


def _benchmark_payload(
    firewall: Firewall, payload: Any, *, iterations: int
) -> dict[str, Any]:
    iterations = max(int(iterations), 1)
    timings_ms: list[float] = []
    for _ in range(iterations):
        started = time.perf_counter()
        firewall.inspect(payload)
        timings_ms.append((time.perf_counter() - started) * 1000)
    total_ms = sum(timings_ms)
    if iterations == 1:
        return {"iterations": 1, "latency_ms": {"sample": timings_ms[0]}}
    return {
        "iterations": iterations,
        "throughput_per_second": (
            iterations / (total_ms / 1000) if total_ms else 0.0
        ),
        "latency_ms": {
            "min": min(timings_ms),
            "p50": _percentile(timings_ms, 50),
            "p95": _percentile(timings_ms, 95),
            "p99": _percentile(timings_ms, 99),
            "max": max(timings_ms),
            "avg": total_ms / iterations,
        },
    }


def format_latency_suite_markdown(report: dict[str, Any]) -> str:
    lines: list[str] = ["# LSDF Latency Suite", ""]
    lines.append(f"_Generated {report['generated_at']}._")
    lines.append("")
    lines.append(
        "Per-profile, per-payload latency. CPU-only — dependency-light "
        "profiles (default/balanced) use regex, entropy, medical patterns, "
        "and contextual-anchored detection; "
        "the optional `broad-pii-ml` profile loads the OpenAI privacy-filter "
        "transformer model on CPU. GPU paths for the optional adapter are "
        "out of scope for this artifact and tracked separately."
    )
    lines.append("")
    lines.append("## Payload matrix")
    lines.append("")
    lines.append("| Name | Bytes | Description |")
    lines.append("| --- | ---: | --- |")
    for entry in report["payloads"]:
        lines.append(
            f"| `{entry['name']}` | {entry['size_bytes']:,} | {_cell(entry['description'])} |"
        )
    lines.append("")

    lines.append(
        f"Each payload below uses `iterations={report['iterations_per_case']}` "
        "of `Firewall.inspect`. No warmup samples are discarded."
    )
    single_sample = report["iterations_per_case"] == 1
    if single_sample:
        lines.append("Each payload has one recorded sample, not a percentile distribution or a throughput estimate.")
    lines.append("")

    for profile in report["profiles"]:
        lines.append(f"## Profile `{profile['profile']}`")
        lines.append("")
        if not profile.get("available"):
            lines.append(f"_Unavailable: {profile.get('error', 'unknown')}._")
            lines.append("")
            continue
        lines.append(
            f"Detector families: {', '.join(profile['detector_families'])}. "
            f"Mode: `{profile['mode']}`."
        )
        lines.append("")
        if single_sample:
            lines.append("| Payload | Sample ms (n=1) |")
            lines.append("| --- | ---: |")
        else:
            lines.append("| Payload | Measured calls/sec | min | p50 | p95 | p99 | max | avg |")
            lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
        for case in profile["cases"]:
            latency = case["latency_ms"]
            if single_sample:
                lines.append(f"| `{case['name']}` | {latency['sample']:.3f} |")
                continue
            lines.append(
                f"| `{case['name']}` | "
                f"{case['throughput_per_second']:.1f} | "
                f"{latency['min']:.3f} | "
                f"{latency['p50']:.3f} | "
                f"{latency['p95']:.3f} | "
                f"{latency['p99']:.3f} | "
                f"{latency['max']:.3f} | "
                f"{latency['avg']:.3f} |"
            )
        lines.append("")
        lines.append("Latency is in milliseconds.")
        lines.append("")

        streaming_cases = profile.get("streaming_cases") or []
        if streaming_cases:
            lines.append("### Streaming per-chunk inspection")
            lines.append("")
            lines.append(
                "Per-chunk wall-clock cost of `StreamingInspectionState.append()` "
                "as the gateway feeds deltas through the holdback buffer (see "
                "`docs/streaming-compatibility.md`). End-to-end columns include "
                "the final `check_pending()` flush."
            )
            lines.append("")
            lines.append(
                "| Stream case | Chunks | Samples | per-chunk p50 | p95 | p99 | max | "
                "end-to-end p50 | p95 | max |"
            )
            lines.append(
                "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"
            )
            for case in streaming_cases:
                per = case["per_chunk_latency_ms"]
                ete = case["end_to_end_latency_ms"]
                lines.append(
                    f"| `{case['name']}` | "
                    f"{case['chunks_per_iteration']} | "
                    f"{case['per_chunk_sample_count']} | "
                    f"{per['p50']:.3f} | "
                    f"{per['p95']:.3f} | "
                    f"{per['p99']:.3f} | "
                    f"{per['max']:.3f} | "
                    f"{ete['p50']:.3f} | "
                    f"{ete['p95']:.3f} | "
                    f"{ete['max']:.3f} |"
                )
            lines.append("")
            lines.append("Latency is in milliseconds.")
            lines.append("")

    lines.append("## Reproduce")
    lines.append("")
    lines.append("Preserve recorded snapshots: write current reports under ignored `.lsdf/current-reports/`. The artifact script uses atomic replacement and keeps default/balanced and full-matrix reports separate.")
    lines.append("")
    lines.append("```bash")
    lines.append("bash scripts/regenerate-artifacts.sh")
    lines.append("```")
    lines.append("")
    lines.append("Dependency-light profiles only:")
    lines.append("")
    lines.append("```bash")
    lines.append("mkdir -p .lsdf/current-reports")
    lines.append(
        "docker compose run --rm cli latency-table --profile default --profile balanced "
        "--iterations 50 --format markdown > .lsdf/current-reports/performance-default-balanced.md.tmp "
        "&& mv .lsdf/current-reports/performance-default-balanced.md.tmp .lsdf/current-reports/performance-default-balanced.md"
    )
    lines.append("```")
    lines.append("")
    lines.append("Full release matrix, including optional ML profiles:")
    lines.append("")
    lines.append("```bash")
    lines.append("mkdir -p .lsdf/current-reports")
    lines.append(
        "docker compose --profile optional run --rm optional-cli "
        "latency-table --profile default --profile balanced --profile broad-pii --profile broad-pii-ml "
        "--iterations 1 --format markdown > .lsdf/current-reports/performance-full-matrix.md.tmp "
        "&& mv .lsdf/current-reports/performance-full-matrix.md.tmp .lsdf/current-reports/performance-full-matrix.md"
    )
    lines.append("```")
    lines.append("")
    lines.append(
        "Override iterations or profiles with `--iterations N` and `--profile NAME` "
        "(repeat per profile). The full-matrix example records one sample per payload; "
        "increase iterations to measure a distribution."
    )
    lines.append("")
    lines.append("## Notes")
    lines.append("")
    lines.append(
        f"- **Streaming-holdback latency** (governed by "
        f"`LSDF_STREAM_HOLDBACK_CHARS`, default {DEFAULT_STREAM_HOLDBACK_CHARS}) "
        "is now characterised in the per-profile *Streaming per-chunk "
        "inspection* table above — `per-chunk p50` is the wall-clock cost of "
        "each `append()` against the holdback buffer; `end-to-end` is the "
        "full chunk-sequence cost including the final `check_pending()` "
        "flush. The holdback bytes themselves are constant per chunk; the "
        "scanner-cost variance is what the table captures."
    )
    lines.append(
        "- **GPU acceleration for the optional ML profile** is not yet "
        "characterized in this report. These are CPU observations, not a "
        "deployment-capacity guarantee."
    )
    lines.append(
        "- **Measurement boundary:** Firewall construction/model loading is outside "
        "the payload timer. First-call initialization may still affect measured "
        "inspection latency; no warmup samples are discarded, so steady-state "
        "behavior is not established. Repeated-run calls/sec measures this serial "
        "loop, excluding provider/network time and deployment concurrency."
    )
    lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def _percentile(values: list[float], percentile: int) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    rank = (percentile / 100) * (len(ordered) - 1)
    lower = int(rank)
    upper = min(lower + 1, len(ordered) - 1)
    weight = rank - lower
    return ordered[lower] + (ordered[upper] - ordered[lower]) * weight


def _payload_bytes(payload: Any) -> int:
    import json

    return len(json.dumps(payload, separators=(",", ":")).encode("utf-8"))


def _cell(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")
