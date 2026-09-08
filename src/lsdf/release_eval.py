# SPDX-License-Identifier: Apache-2.0
"""Release-quality EVAL.md generator.

Runs one or more policy profiles against one or more threat corpora plus
one or more benign corpora and a benchmark payload, then emits a
per-detector-family signal/noise report plus latency. Intended to land
at the repo root as `EVAL.md` and be regenerated each release.

The headline detection metric is value-level containment: sensitive
values present before inspection but absent after inspection count as
contained. The per-entity table is case-level because the bundled corpora
annotate expected values and expected entity types, not span offsets or
entity-to-value links; it therefore reports both full-case containment
and exact entity tagging so broad blockers do not look like missed leaks.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .engine import Firewall
from .observability import sanitize_observability
from .policy import load_effective_policy, load_policy_profile, load_profile_gate_promise


DEFAULT_THREAT_DATASET = Path("evals/piece_b_replay.json")
DEFAULT_THREAT_DATASETS = (
    Path("evals/piece_b_replay.json"),
    Path("evals/medical_phi_replay.json"),
    Path("evals/nemotron_pii.json"),
    Path("evals/br_agentic_pii.json"),
)
DEFAULT_BENIGN_DATASETS = (
    Path("evals/false_positive.json"),
    Path("evals/utility_matrix.json"),
)
DEFAULT_BENCHMARK_PAYLOAD = Path("examples/openai_request.json")
DEFAULT_PROFILES = ("default", "balanced", "broad-pii", "broad-pii-ml")
DEFAULT_ITERATIONS = 50


def release_evaluation(
    *,
    profiles: list[str] | tuple[str, ...] = DEFAULT_PROFILES,
    threat_datasets: list[Path] | tuple[Path, ...] | None = None,
    threat_dataset: Path | None = None,
    benign_datasets: list[Path] | tuple[Path, ...] = DEFAULT_BENIGN_DATASETS,
    benchmark_payload: Path = DEFAULT_BENCHMARK_PAYLOAD,
    iterations: int = DEFAULT_ITERATIONS,
) -> dict[str, Any]:
    if threat_datasets is None:
        # Singular `threat_dataset=` is a thin compatibility shim for
        # callers from before the multi-corpus refactor; new callers
        # should pass `threat_datasets=`.
        if threat_dataset is not None:
            threat_datasets = (threat_dataset,)
        else:
            threat_datasets = DEFAULT_THREAT_DATASETS
    threats = [(path, _load_dataset(path, role="threat")) for path in threat_datasets]
    benign = [(path, _load_dataset(path, role="benign")) for path in benign_datasets]
    bench_payload = (
        json.loads(benchmark_payload.read_text(encoding="utf-8"))
        if benchmark_payload.exists()
        else None
    )

    profile_reports: list[dict[str, Any]] = []
    for profile_name in profiles:
        profile_reports.append(
            _evaluate_profile(
                profile_name,
                threats=threats,
                benign=benign,
                benchmark_payload=bench_payload,
                iterations=iterations,
            )
        )

    return {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "threat_datasets": [
            {
                "path": str(path),
                "name": data.get("name", path.name),
                "case_count": len(data.get("cases", [])),
                "source": data.get("source"),
                "source_license": data.get("source_license"),
                "source_url": data.get("source_url"),
                "selection_note": data.get("selection_note"),
            }
            for path, data in threats
        ],
        "benign_datasets": [
            {
                "path": str(path),
                "name": data.get("name", path.name),
                "case_count": len(data.get("cases", [])),
            }
            for path, data in benign
        ],
        "benchmark": {
            "payload_path": str(benchmark_payload),
            "iterations": iterations,
            "available": bench_payload is not None,
        },
        "release_gate": _release_gate(profile_reports),
        "profiles": profile_reports,
    }


def _evaluate_profile(
    profile_name: str,
    *,
    threats: list[tuple[Path, dict[str, Any]]],
    benign: list[tuple[Path, dict[str, Any]]],
    benchmark_payload: Any,
    iterations: int,
) -> dict[str, Any]:
    try:
        gate_promise = load_profile_gate_promise(profile_name)
    except ValueError as exc:
        if "Unknown policy profile" not in str(exc):
            raise
        gate_promise = None
    gate_promise_dict = gate_promise.as_dict() if gate_promise else None
    try:
        policy = load_policy_profile(profile_name)
    except Exception as exc:
        try:
            policy = load_effective_policy(profile_name)
        except Exception as exc2:
            return {
                "profile": profile_name,
                "available": False,
                "gate_promise": gate_promise_dict,
                "error": f"{type(exc2).__name__}: {exc2}",
            }
    try:
        firewall = Firewall(policy)
    except Exception as exc:
        return {
            "profile": profile_name,
            "available": False,
            "gate_promise": gate_promise_dict,
            "error": f"{type(exc).__name__}: {exc}",
        }

    detector_summary = firewall.detector_summary()

    threat_reports: list[dict[str, Any]] = []
    threat_findings_by_family: dict[str, int] = {}
    per_entity_recall: dict[str, dict[str, int]] = {}
    for path, data in threats:
        report = firewall.evaluate(data["cases"])
        by_family = report.get("summary", {}).get("by_detector_family", {})
        recall = _value_recall(
            report["sensitive_values_leaked_before"],
            report["sensitive_values_leaked_after"],
        )
        threat_reports.append(
            {
                "path": str(path),
                "name": data.get("name", path.name),
                "case_count": report["case_count"],
                "passed": report["passed"],
                "blocked": report["blocked"],
                "sensitive_values_leaked_before": report[
                    "sensitive_values_leaked_before"
                ],
                "sensitive_values_leaked_after": report[
                    "sensitive_values_leaked_after"
                ],
                "cases_with_sensitive_values_after": report[
                    "cases_with_sensitive_values_after"
                ],
                "value_recall": recall,
                "by_detector_family": dict(by_family),
            }
        )
        for family, count in by_family.items():
            threat_findings_by_family[family] = (
                threat_findings_by_family.get(family, 0) + int(count)
            )
        _accumulate_entity_recall(per_entity_recall, data["cases"], report["results"])

    benign_reports = []
    benign_findings_by_family: dict[str, int] = {}
    benign_total_cases = 0
    benign_total_findings = 0
    for path, data in benign:
        report = firewall.evaluate(data["cases"])
        by_family = report.get("summary", {}).get("by_detector_family", {})
        benign_findings_total = sum(int(c) for c in by_family.values())
        benign_reports.append(
            {
                "path": str(path),
                "name": data.get("name", path.name),
                "case_count": report["case_count"],
                "passed": report["passed"],
                "failed": report["failed"],
                "blocked": report["blocked"],
                "by_detector_family": dict(by_family),
            }
        )
        for family, count in by_family.items():
            benign_findings_by_family[family] = (
                benign_findings_by_family.get(family, 0) + int(count)
            )
        benign_total_cases += int(report["case_count"])
        benign_total_findings += benign_findings_total

    benign_fp_case_rate = _safe_div(
        sum(int(b["failed"]) for b in benign_reports),
        benign_total_cases,
    )
    detection_metrics = {
        "benign_case_count": benign_total_cases,
        "benign_findings": benign_total_findings,
        "benign_fp_case_rate": benign_fp_case_rate,
        "benign_specificity": (
            None if benign_fp_case_rate is None else 1.0 - benign_fp_case_rate
        ),
        "per_corpus": [
            {
                "name": threat["name"],
                "value_recall": threat["value_recall"],
                "f2": _f_beta(
                    threat["value_recall"],
                    None if benign_fp_case_rate is None else 1.0 - benign_fp_case_rate,
                    beta=2.0,
                ),
            }
            for threat in threat_reports
        ],
    }
    entity_recall_table = sorted(
        (
            {
                "entity": entity,
                "expected_cases": stats["expected"],
                "contained_cases": stats["contained"],
                "containment_recall": _safe_div(
                    stats["contained"], stats["expected"]
                ),
                "exact_tag_cases": stats["exact_tag"],
                "exact_tag_recall": _safe_div(stats["exact_tag"], stats["expected"]),
                # Backward-compatible aliases for JSON consumers that read
                # the old exact-tag-only metric before the table split.
                "detected_cases": stats["exact_tag"],
                "recall": _safe_div(stats["exact_tag"], stats["expected"]),
            }
            for entity, stats in per_entity_recall.items()
        ),
        key=lambda row: (-row["expected_cases"], row["entity"]),
    )

    families = sorted(set(threat_findings_by_family) | set(benign_findings_by_family))
    family_table = []
    for family in families:
        threat_findings = int(threat_findings_by_family.get(family, 0))
        benign_findings = int(benign_findings_by_family.get(family, 0))
        family_table.append(
            {
                "family": family,
                "threat_findings": threat_findings,
                "benign_findings": benign_findings,
                "signal_to_noise": _ratio(threat_findings, benign_findings),
            }
        )

    bench: dict[str, Any] | None = None
    if benchmark_payload is not None:
        bench = _benchmark(firewall, benchmark_payload, iterations=iterations)

    return {
        "profile": profile_name,
        "available": True,
        "mode": policy.mode,
        "gate_promise": policy.gate_promise.as_dict() if policy.gate_promise else None,
        "detector_families": detector_summary["detector_families"],
        "detector_id_count": len(detector_summary["detector_ids"]),
        "threats": threat_reports,
        "benign": benign_reports,
        "by_detector_family": family_table,
        "detection_metrics": detection_metrics,
        "entity_recall": entity_recall_table,
        "benchmark": bench,
    }


def _benchmark(firewall: Firewall, payload: Any, *, iterations: int) -> dict[str, Any]:
    timings_ms: list[float] = []
    for _ in range(max(iterations, 1)):
        started = time.perf_counter()
        firewall.inspect(payload)
        timings_ms.append((time.perf_counter() - started) * 1000)
    total_ms = sum(timings_ms)
    return {
        "iterations": len(timings_ms),
        "throughput_per_second": (
            len(timings_ms) / (total_ms / 1000) if total_ms else 0.0
        ),
        "latency_ms": {
            "min": min(timings_ms),
            "p50": _percentile(timings_ms, 50),
            "p95": _percentile(timings_ms, 95),
            "max": max(timings_ms),
            "avg": total_ms / len(timings_ms),
        },
    }


def format_release_evaluation_markdown(report: dict[str, Any]) -> str:
    lines: list[str] = ["# LSDF Eval Report", ""]
    lines.append(f"_Generated {report['generated_at']}._")
    lines.append("")
    lines.append(
        "Signal-vs-noise results for the profiles and corpora listed in this report."
    )
    lines.append("")
    gate = report.get("release_gate", {})
    lines.append("## Release Gate")
    lines.append("")
    lines.append(
        "Release-gated profiles must hold the value-level recall floor declared "
        "in their YAML `gate_promise:` block on every promised threat corpus, "
        "plus the promised benign specificity floor."
    )
    lines.append("")
    lines.append(
        "Default reports use the bundled redistributable corpora. "
        "broad-pii and broad-pii-ml use span-scope redaction and are gated "
        "on their YAML promises. Healthcare uses surface-scope PHI "
        "containment and additionally promises Nemotron-PII and the "
        "separately supplied ai4privacy multilingual benchmark. "
        "ai4privacy source data is not bundled. A healthcare run without "
        "that external corpus fails its unchanged gate; obtain appropriate "
        "rights and supply it explicitly. Only the corpora listed below "
        "were evaluated in this run."
    )
    lines.append("")
    lines.append("| Profile | Status | Detail |")
    lines.append("| --- | --- | --- |")
    for row in gate.get("profiles", []):
        status = "PASS" if row.get("passed") else "FAIL"
        detail = ", ".join(row.get("failures", [])) or "all floors held"
        lines.append(f"| {_cell(row['profile'])} | {status} | {_cell(detail)} |")
    if not gate.get("profiles"):
        lines.append("| _none_ | n/a | no release-gated profiles in this run |")
    lines.append("")

    lines.append("## Corpora")
    lines.append("")
    lines.append("| Corpus | Path | Cases | Role | Source |")
    lines.append("| --- | --- | ---: | --- | --- |")
    for threat in report["threat_datasets"]:
        source_cell = _source_cell(threat)
        lines.append(
            f"| {_cell(threat['name'])} | `{threat['path']}` | "
            f"{threat['case_count']} | threat | {source_cell} |"
        )
    for benign in report["benign_datasets"]:
        lines.append(
            f"| {_cell(benign['name'])} | `{benign['path']}` | "
            f"{benign['case_count']} | benign | _internal_ |"
        )
    lines.append("")

    selection_notes = [
        threat
        for threat in report["threat_datasets"]
        if threat.get("selection_note")
    ]
    if selection_notes:
        lines.append("## External Corpus Selection")
        lines.append("")
        for threat in selection_notes:
            lines.append(
                f"- `{_cell(threat['name'])}`: {_cell(threat['selection_note'])}"
            )
        lines.append("")

    lines.append("## Threat-corpus containment")
    lines.append("")
    lines.append(
        "| Profile | Corpus | Cases | Blocked | Sensitive values before | "
        "Sensitive values after | Cases with leak after |"
    )
    lines.append("| --- | --- | ---: | ---: | ---: | ---: | ---: |")
    for profile in report["profiles"]:
        if not profile.get("available"):
            lines.append(
                f"| {_cell(profile['profile'])} | _unavailable_ | n/a | n/a | n/a | n/a | n/a |"
            )
            continue
        for threat in profile["threats"]:
            lines.append(
                f"| {_cell(profile['profile'])} | "
                f"{_cell(threat['name'])} | "
                f"{threat['case_count']} | "
                f"{threat['blocked']} | "
                f"{threat['sensitive_values_leaked_before']} | "
                f"{threat['sensitive_values_leaked_after']} | "
                f"{threat['cases_with_sensitive_values_after']} |"
            )
    lines.append("")

    lines.append(
        "## Detection metrics (presidio-research β=2 convention; "
        "value-level recall, specificity in place of precision)"
    )
    lines.append("")
    lines.append(
        "Per-corpus value-level recall, benign specificity (1 minus the "
        "FP case rate across benign corpora), and recall-weighted F2. "
        "Recall = (sensitive values present pre-inspection − sensitive "
        "values present post-inspection) ÷ pre-inspection. Specificity "
        "treats every benign case that produced one or more findings as "
        "a false positive. F2 follows Microsoft presidio-research's "
        "default β=2 — recall is weighted more heavily than precision "
        "because LSDF's threat model treats a missed leak as strictly "
        "worse than a benign FP."
    )
    lines.append("")
    lines.append(
        "| Profile | Corpus | Recall | Specificity | F2 |"
    )
    lines.append("| --- | --- | ---: | ---: | ---: |")
    for profile in report["profiles"]:
        if not profile.get("available"):
            continue
        metrics = profile.get("detection_metrics") or {}
        specificity = metrics.get("benign_specificity")
        for row in metrics.get("per_corpus", []):
            lines.append(
                f"| {_cell(profile['profile'])} | "
                f"{_cell(row['name'])} | "
                f"{_format_metric(row['value_recall'])} | "
                f"{_format_metric(specificity)} | "
                f"{_format_metric(row['f2'])} |"
            )
    lines.append("")

    lines.append(
        "## Per-entity-type containment and exact-tag recall "
        "(LSDF canonical vocabulary)"
    )
    lines.append("")
    lines.append(
        "Case-level metrics per entity type, aggregated across every "
        "threat corpus. \"Expected\" counts cases whose annotation "
        "lists that entity in `expected_entities`. \"Contained\" "
        "credits the case when LSDF blocked it or when every annotated "
        "sensitive value that was present before inspection is absent "
        "after inspection. \"Exact-tag\" counts cases where "
        "`Firewall.evaluate` produced at least one finding whose LSDF "
        "entity exactly matched the annotation. Exact tags measure "
        "attribution, not leak prevention: broad PHI, contextual, or "
        "whole-surface policies can contain MRN, bank-account, DOB, or "
        "other values under a broader finding without preserving the "
        "narrow original label. Because the bundled corpora annotate "
        "values rather than offsets or entity-to-value links, "
        "containment is a conservative full-case proxy."
    )
    lines.append("")
    for profile in report["profiles"]:
        if not profile.get("available"):
            continue
        rows = profile.get("entity_recall") or []
        if not rows:
            continue
        lines.append(f"### {profile['profile']}")
        lines.append("")
        lines.append(
            "| Entity | Expected cases | Contained cases | "
            "Containment recall | Exact-tag cases | Exact-tag recall |"
        )
        lines.append("| --- | ---: | ---: | ---: | ---: | ---: |")
        for row in rows:
            lines.append(
                f"| {_cell(row['entity'])} | "
                f"{row['expected_cases']} | "
                f"{row['contained_cases']} | "
                f"{_format_metric(row['containment_recall'])} | "
                f"{row['exact_tag_cases']} | "
                f"{_format_metric(row['exact_tag_recall'])} |"
            )
        lines.append("")

    lines.append("## Benign-corpus findings (lower is better)")
    lines.append("")
    lines.append(
        "Findings on benign cases are FP candidates. `expected_no_findings: true` "
        "is preferred for these cases; any finding here surfaces a noise source."
    )
    lines.append("")
    lines.append("| Profile | Corpus | Cases | Passed | Failed | Findings by family |")
    lines.append("| --- | --- | ---: | ---: | ---: | --- |")
    for profile in report["profiles"]:
        if not profile.get("available"):
            continue
        for benign in profile["benign"]:
            family_summary = (
                ", ".join(
                    f"{family}={count}"
                    for family, count in sorted(benign["by_detector_family"].items())
                )
                or "_none_"
            )
            lines.append(
                f"| {_cell(profile['profile'])} | {_cell(benign['name'])} | "
                f"{benign['case_count']} | {benign['passed']} | {benign['failed']} | "
                f"{_cell(family_summary)} |"
            )
    lines.append("")

    lines.append("## Per-detector-family signal vs noise")
    lines.append("")
    lines.append(
        "Counts findings on the threat corpora (signal — aggregated across "
        "every threat dataset) vs the benign corpora (noise) for each "
        "detector family. The ratio is a coarse FP-load proxy: high signal "
        "with zero benign findings is the goal."
    )
    lines.append("")
    for profile in report["profiles"]:
        if not profile.get("available"):
            continue
        lines.append(f"### {profile['profile']}")
        lines.append("")
        lines.append("| Detector family | Threat findings | Benign findings | Signal/noise |")
        lines.append("| --- | ---: | ---: | --- |")
        for row in profile["by_detector_family"]:
            lines.append(
                f"| {_cell(row['family'])} | {row['threat_findings']} | "
                f"{row['benign_findings']} | {row['signal_to_noise']} |"
            )
        lines.append("")

    lines.append("## System-level detector recall")
    lines.append("")
    lines.append(
        "See `docs/system-recall.md` for per-detector recall and specificity "
        "against foundation fixtures, independent of profile composition. The "
        "release gates above are profile-level promise gates; system-recall.md "
        "is the engine-capability contract."
    )
    lines.append("")

    lines.append("## Latency")
    lines.append("")
    bench_meta = report.get("benchmark", {})
    if not bench_meta.get("available"):
        lines.append(f"_No benchmark payload at `{bench_meta.get('payload_path')}`._")
        lines.append("")
    else:
        lines.append(
            f"Benchmark payload: `{bench_meta['payload_path']}` × "
            f"{bench_meta['iterations']} iterations."
        )
        lines.append("")
        lines.append(
            "| Profile | Throughput/sec | min ms | p50 ms | p95 ms | max ms | avg ms |"
        )
        lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: |")
        for profile in report["profiles"]:
            if not profile.get("available") or profile.get("benchmark") is None:
                continue
            bench = profile["benchmark"]
            latency = bench["latency_ms"]
            lines.append(
                f"| {_cell(profile['profile'])} | "
                f"{bench['throughput_per_second']:.1f} | "
                f"{latency['min']:.3f} | {latency['p50']:.3f} | "
                f"{latency['p95']:.3f} | {latency['max']:.3f} | "
                f"{latency['avg']:.3f} |"
            )
        lines.append("")

    lines.append("## Reproduce")
    lines.append("")
    lines.append("Create the ignored output directory first with `mkdir -p .lsdf`.")
    lines.append("")
    lines.append("Dependency-light profiles only:")
    lines.append("")
    lines.append("```bash")
    lines.append(
        "docker compose run --rm cli "
        "eval-report --profile default --profile balanced --format markdown > .lsdf/eval-current.md"
    )
    lines.append("```")
    lines.append("")
    lines.append("Full release matrix, including optional ML profiles:")
    lines.append("")
    lines.append("```bash")
    lines.append(
        "docker compose --profile optional run --rm optional-cli "
        "eval-report --format markdown > .lsdf/eval-current.md"
    )
    lines.append("```")
    lines.append("")
    lines.append(
        "Pass `--profile NAME` once per profile (default: `default`, "
        "`balanced`, `broad-pii`, `broad-pii-ml`), "
        "`--threat-dataset PATH` (repeatable; default: `piece_b_replay`, "
        "`medical_phi_replay`, `nemotron_pii`, "
        "`br_agentic_pii`), "
        "`--benign-dataset PATH` (repeatable; default: `false_positive`, "
        "`utility_matrix`), `--benchmark-payload PATH`, or `--iterations N` "
        "to override. Explicit threat paths replace all defaults; include each bundled path "
        "and an appropriately licensed local external path to evaluate healthcare. "
        "Keep external data and generated reports under ignored `.lsdf/`."
    )
    lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def _release_gate(profile_reports: list[dict[str, Any]]) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for profile in profile_reports:
        promise = profile.get("gate_promise")
        if promise is None:
            continue
        profile_name = profile["profile"]
        failures: list[str] = []
        gated_corpora = {str(corpus) for corpus in promise["corpora"]}
        recall_floor = float(promise["recall_floor"])
        specificity_floor = float(promise["specificity_floor"])
        if not profile.get("available"):
            failures.append("profile unavailable")
            rows.append(
                {
                    "profile": profile_name,
                    "passed": False,
                    "failures": failures,
                    "gated_corpora": sorted(gated_corpora),
                }
            )
            continue
        metrics = profile.get("detection_metrics") or {}
        specificity = metrics.get("benign_specificity")
        if specificity is None or specificity < specificity_floor:
            failures.append(f"specificity {specificity if specificity is not None else 'n/a'}")
        present_gated_corpora: set[str] = set()
        for row in metrics.get("per_corpus", []):
            corpus_name = row.get("name")
            if corpus_name not in gated_corpora:
                continue
            present_gated_corpora.add(corpus_name)
            recall = row.get("value_recall")
            if recall is None or recall < recall_floor:
                failures.append(
                    f"{row['name']} recall {recall if recall is not None else 'n/a'}"
                )
        for missing in sorted(gated_corpora - present_gated_corpora):
            failures.append(f"{missing} recall missing")
        rows.append(
            {
                "profile": profile_name,
                "passed": not failures,
                "failures": failures,
                "gated_corpora": sorted(gated_corpora),
            }
        )
    return {"profiles": rows, "passed": all(row["passed"] for row in rows)}


def _load_dataset(path: Path, *, role: str = "dataset") -> dict[str, Any]:
    # The CLI catches FileNotFoundError + ValueError and prints a
    # message; programmatic callers see whatever bubbles up here, so
    # the role + path keeps the failure self-locating regardless of
    # which surface raised.
    if not path.exists():
        raise FileNotFoundError(f"{role.capitalize()} dataset not found: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def _ratio(signal: int, noise: int) -> str:
    if signal == 0 and noise == 0:
        return "n/a"
    if noise == 0:
        return "∞ (no benign findings)"
    return f"{signal / noise:.1f}:1"


def _percentile(values: list[float], percentile: int) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    rank = (percentile / 100) * (len(ordered) - 1)
    lower = int(rank)
    upper = min(lower + 1, len(ordered) - 1)
    weight = rank - lower
    return ordered[lower] + (ordered[upper] - ordered[lower]) * weight


def _source_cell(threat_meta: dict[str, Any]) -> str:
    source = threat_meta.get("source")
    license_str = threat_meta.get("source_license")
    if not source:
        return "_internal_"
    if license_str:
        return f"`{source}` ({license_str})"
    return f"`{source}`"


def _cell(value: Any) -> str:
    return str(value).replace("|", "\\|")


def _safe_div(numerator: float, denominator: float) -> float | None:
    if denominator == 0:
        return None
    return numerator / denominator


def _format_metric(value: float | None) -> str:
    if value is None:
        return "n/a"
    return f"{value:.3f}"


def _value_recall(before: int, after: int) -> float | None:
    # Value-level recall on a threat corpus: fraction of pre-inspection
    # sensitive values that are NOT present in the post-inspection
    # payload. Mirrors the presidio-research convention of recall = TP /
    # (TP + FN), with sensitive values that survive treated as FN.
    if before == 0:
        return None
    return (before - after) / before


def _f_beta(recall: float | None, specificity: float | None, *, beta: float) -> float | None:
    # Presidio-research reports F2 (beta=2) by default — recall-weighted,
    # which matches the LSDF threat model where missing a leak is
    # strictly worse than firing on benign traffic. Substituting
    # specificity (1 - benign_fp_case_rate) for precision keeps the
    # metric well-defined when `expected_no_findings: true` corpora are
    # the only available "ground truth" for the FP side.
    if recall is None or specificity is None:
        return None
    if recall == 0 and specificity == 0:
        return 0.0
    beta2 = beta * beta
    denominator = beta2 * specificity + recall
    if denominator == 0:
        return 0.0
    return (1 + beta2) * (specificity * recall) / denominator


def _accumulate_entity_recall(
    accumulator: dict[str, dict[str, int]],
    cases: list[dict[str, Any]],
    case_results: list[dict[str, Any]],
) -> None:
    # Per-entity-type case-level accounting on the LSDF canonical
    # vocabulary. For each case, "expected" entities come from the
    # corpus annotation. "contained" follows value-level containment at
    # case granularity: a blocked case is credited, as is a transformed
    # case where all annotated sensitive values are absent afterwards.
    # "exact_tag" is narrower attribution: at least one finding entity
    # must exactly match the expected entity. We count cases (not
    # findings) so the metric is comparable across corpora regardless of
    # how many spans a given case happens to contain.
    # `id` is the only stable handle a case result carries — skip
    # entries without one rather than collapsing every id-less result
    # into a single `by_id[None]` slot (last-writer-wins). Bundled
    # corpora all carry ids; this guard just keeps the metric honest
    # against future corpora that don't.
    by_id = {
        result["id"]: result
        for result in case_results
        if result.get("id") is not None
    }
    for case in cases:
        case_id = case.get("id")
        if case_id is None:
            continue
        case_result = by_id.get(case_id)
        if case_result is None:
            continue
        expected = set(case.get("expected_entities") or [])
        exact_tags = set(case_result.get("finding_entities") or [])
        contained = _case_fully_contained(case_result)
        for entity in expected:
            bucket = accumulator.setdefault(
                entity, {"expected": 0, "contained": 0, "exact_tag": 0}
            )
            bucket["expected"] += 1
            if contained:
                bucket["contained"] += 1
            if entity in exact_tags:
                bucket["exact_tag"] += 1


def _case_fully_contained(case_result: dict[str, Any]) -> bool:
    if bool(case_result.get("blocked")):
        return True
    before = int(case_result.get("sensitive_values_leaked_before_count") or 0)
    after = int(case_result.get("sensitive_values_leaked_after_count") or 0)
    return before > 0 and after == 0
