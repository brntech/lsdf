# SPDX-License-Identifier: Apache-2.0
"""Measurement harness for broad-pii-ml score_threshold lever evaluation.

The optional ML profile fires on plain technical/business prose at high model
confidence (~0.99). Four candidate levers were considered; this module
implements the cheapest of them — a `score_threshold` sweep on the OpenAI
privacy-filter adapter — so we can decide whether tightening the threshold
recovers FP rate without losing threat-corpus containment.

Sweep mechanics:
  - load the privacy-filter model once (~2 s),
  - for each `--threshold` value, construct an `OpenAIPrivacyFilterDetector`
    with that threshold and run a `Firewall` configured with the broad-pii-ml
    profile against `evals/piece_b_replay.json` (recall) +
    `evals/false_positive.json` + `evals/utility_matrix.json` (FP).
  - emit per-threshold containment + FP-by-family.

The other three levers (per-category min_confidence, regex/entropy
corroboration, tech-prose context suppressor) require source-side changes and
are out of scope for this harness.
"""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .engine import Firewall
from .policy import load_policy_profile
from .scanners.openai_privacy_filter import (
    OpenAIPrivacyFilterDetector,
    build_installed_openai_privacy_filter_detector,
)


DEFAULT_THRESHOLDS = (0.50, 0.70, 0.85, 0.95)
DEFAULT_PROFILE = "broad-pii-ml"
DEFAULT_THREAT_DATASET = Path("evals/piece_b_replay.json")
DEFAULT_BENIGN_DATASETS = (
    Path("evals/false_positive.json"),
    Path("evals/utility_matrix.json"),
)


def run_threshold_sweep(
    *,
    thresholds: list[float] | tuple[float, ...] = DEFAULT_THRESHOLDS,
    threat_dataset: Path = DEFAULT_THREAT_DATASET,
    benign_datasets: list[Path] | tuple[Path, ...] = DEFAULT_BENIGN_DATASETS,
    profile_name: str = DEFAULT_PROFILE,
) -> dict[str, Any]:
    threat = json.loads(threat_dataset.read_text(encoding="utf-8"))
    benign = [
        (path, json.loads(path.read_text(encoding="utf-8"))) for path in benign_datasets
    ]
    base_detector = build_installed_openai_privacy_filter_detector()
    policy = load_policy_profile(profile_name)

    sweep_results: list[dict[str, Any]] = []
    for threshold in thresholds:
        scoped_detector = replace(base_detector, score_threshold=float(threshold))
        firewall = Firewall(
            policy,
            detector_providers={"openai_privacy_filter": scoped_detector},
        )
        threat_report = firewall.evaluate(threat["cases"])
        benign_summaries = []
        total_benign_findings_by_family: dict[str, int] = {}
        for path, data in benign:
            report = firewall.evaluate(data["cases"])
            by_family = dict(report.get("summary", {}).get("by_detector_family", {}))
            benign_summaries.append(
                {
                    "path": str(path),
                    "name": data.get("name", path.name),
                    "case_count": report["case_count"],
                    "passed": report["passed"],
                    "failed": report["failed"],
                    "by_detector_family": by_family,
                }
            )
            for family, count in by_family.items():
                total_benign_findings_by_family[family] = (
                    total_benign_findings_by_family.get(family, 0) + int(count)
                )
        sweep_results.append(
            {
                "score_threshold": float(threshold),
                "threat": {
                    "case_count": threat_report["case_count"],
                    "blocked": threat_report["blocked"],
                    "sensitive_values_leaked_before": threat_report[
                        "sensitive_values_leaked_before"
                    ],
                    "sensitive_values_leaked_after": threat_report[
                        "sensitive_values_leaked_after"
                    ],
                    "cases_with_sensitive_values_after": threat_report[
                        "cases_with_sensitive_values_after"
                    ],
                },
                "benign": benign_summaries,
                "benign_findings_by_family_total": total_benign_findings_by_family,
            }
        )

    return {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "profile": profile_name,
        "threat_dataset": {
            "path": str(threat_dataset),
            "case_count": len(threat.get("cases", [])),
        },
        "benign_datasets": [
            {
                "path": str(path),
                "name": data.get("name", path.name),
                "case_count": len(data.get("cases", [])),
            }
            for path, data in benign
        ],
        "results": sweep_results,
    }


def format_threshold_sweep_markdown(report: dict[str, Any]) -> str:
    lines: list[str] = ["# Broad-pii-ml score_threshold sweep", ""]
    lines.append(f"_Generated {report['generated_at']}._")
    lines.append("")
    lines.append(
        f"Profile: `{report['profile']}`. Threat dataset: "
        f"`{report['threat_dataset']['path']}` ({report['threat_dataset']['case_count']} cases). "
        f"Benign datasets: "
        + ", ".join(
            f"`{ds['path']}` ({ds['case_count']})"
            for ds in report["benign_datasets"]
        )
        + "."
    )
    lines.append("")
    lines.append(
        "Sweep varies `OpenAIPrivacyFilterDetector.score_threshold` while "
        "keeping every other detector and rule unchanged. Goal: lowest "
        "threshold whose **threat sensitive_values_leaked_after stays at 0** "
        "(no recall regression) while **benign findings drop ≥50%** vs the "
        "baseline (0.50)."
    )
    lines.append("")
    lines.append(
        "| score_threshold | threat after-leak (cases / values) | "
        "benign findings (regex / entropy / medical-regex / privacy-filter / total) |"
    )
    lines.append(
        "| ---: | --- | --- |"
    )
    for entry in report["results"]:
        threat = entry["threat"]
        families = entry["benign_findings_by_family_total"]
        regex = families.get("regex", 0)
        entropy = families.get("entropy", 0)
        medical = families.get("medical-regex", 0)
        ml = families.get("openai_privacy_filter", 0)
        total = sum(families.values())
        lines.append(
            f"| {entry['score_threshold']:.2f} | "
            f"{threat['cases_with_sensitive_values_after']} / {threat['sensitive_values_leaked_after']} | "
            f"{regex} / {entropy} / {medical} / {ml} / {total} |"
        )
    lines.append("")
    lines.append("## Per-corpus benign breakdown")
    lines.append("")
    lines.append(
        "| score_threshold | corpus | passed / cases | findings by family |"
    )
    lines.append("| ---: | --- | --- | --- |")
    for entry in report["results"]:
        for benign in entry["benign"]:
            family_summary = (
                ", ".join(
                    f"{family}={count}"
                    for family, count in sorted(benign["by_detector_family"].items())
                )
                or "_none_"
            )
            lines.append(
                f"| {entry['score_threshold']:.2f} | {benign['name']} | "
                f"{benign['passed']} / {benign['case_count']} | {family_summary} |"
            )
    lines.append("")
    lines.append("## Reproduce")
    lines.append("")
    lines.append("```bash")
    lines.append(
        "docker compose --profile optional run --rm optional-cli "
        "fp-lever-table --threshold 0.50 --threshold 0.70 --threshold 0.85 "
        "--threshold 0.95 --format markdown 2>/dev/null"
    )
    lines.append("```")
    lines.append("")
    return "\n".join(lines).rstrip() + "\n"
