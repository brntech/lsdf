"""Build docs/comparative-protection.md from the bundled LSDF corpora.

This is a documentation generator, not a new CLI surface. Run it through
Docker Compose so optional detector dependencies come from the project image:

    docker compose --profile optional run --rm --entrypoint python optional-cli \
        scripts/build_comparative_protection.py \
        --output docs/comparative-protection.md \
        --seed 0
"""

from __future__ import annotations

import argparse
import json
import random
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from lsdf.detectors import DetectorUnavailableError, build_detector_registry
from lsdf.engine import Firewall
from lsdf.policy import load_policy_profile


@dataclass(frozen=True)
class DetectorStack:
    name: str
    families: tuple[str, ...]
    label: str


THREAT_DATASETS = (
    Path("evals/piece_b_replay.json"),
    Path("evals/medical_phi_replay.json"),
    Path("evals/nemotron_pii.json"),
    Path("evals/br_agentic_pii.json"),
)
BENIGN_DATASETS = (
    Path("evals/false_positive.json"),
    Path("evals/utility_matrix.json"),
)
DETECTOR_STACKS = (
    DetectorStack("regex_only", ("regex",), "Naive regex-only baseline"),
    DetectorStack("presidio", ("presidio",), "Microsoft Presidio analyzer"),
    DetectorStack(
        "lsdf_dependency_light",
        ("regex", "entropy", "medical-regex", "contextual-anchored"),
        "LSDF dependency-light detector stack",
    ),
    DetectorStack(
        "lsdf_broad_pii",
        ("regex", "entropy", "medical-regex", "contextual-anchored", "contextual-broad", "gliner"),
        "LSDF local broad-pii detector stack",
    ),
)
REQUIRED_STACKS = frozenset(stack.name for stack in DETECTOR_STACKS)
DEFAULT_SEED = 0


def build_report(*, seed: int = DEFAULT_SEED) -> dict[str, Any]:
    _seed_optional_detectors(seed)
    policy = load_policy_profile("broad-pii")
    stacks = [_build_stack_report(policy, stack) for stack in DETECTOR_STACKS]
    _assert_required_stacks_available(stacks)
    return {
        "policy_profile": policy.name,
        "seed": seed,
        "method": (
            "All detector stacks run under the same LSDF broad-pii policy/actions "
            "so the comparison isolates detector signal on identical surfaces."
        ),
        "threat_datasets": [str(path) for path in THREAT_DATASETS],
        "benign_datasets": [str(path) for path in BENIGN_DATASETS],
        "stacks": stacks,
    }


def _build_stack_report(policy: Any, stack: DetectorStack) -> dict[str, Any]:
    base: dict[str, Any] = {
        "name": stack.name,
        "label": stack.label,
        "families": list(stack.families),
        "status": "ok",
        "threats": [],
        "benign": [],
    }
    try:
        registry = build_detector_registry(stack.families)
    except (DetectorUnavailableError, ValueError) as exc:
        return {**base, "status": "unavailable", "reason": str(exc)}

    firewall = Firewall(policy, detector_registry=registry)
    for path in THREAT_DATASETS:
        dataset = _read_dataset(path)
        base["threats"].append(_threat_row(stack, path, dataset, firewall))
    for path in BENIGN_DATASETS:
        dataset = _read_dataset(path)
        base["benign"].append(_benign_row(stack, path, dataset, firewall))
    return base


def _assert_required_stacks_available(stacks: list[dict[str, Any]]) -> None:
    unavailable = [
        stack
        for stack in stacks
        if stack["name"] in REQUIRED_STACKS and stack["status"] != "ok"
    ]
    if not unavailable:
        return
    details = "; ".join(
        f"{stack['name']}: {stack.get('reason', 'unavailable')}"
        for stack in unavailable
    )
    raise RuntimeError(f"required comparator stack unavailable: {details}")


def _threat_row(
    stack: DetectorStack,
    path: Path,
    dataset: dict[str, Any],
    firewall: Firewall,
) -> dict[str, Any]:
    report = firewall.evaluate(dataset["cases"])
    before = int(report["sensitive_values_leaked_before"])
    after = int(report["sensitive_values_leaked_after"])
    return {
        "stack": stack.name,
        "corpus": dataset.get("name", path.stem),
        "path": str(path),
        "cases": int(report["case_count"]),
        "before": before,
        "after": after,
        "recall": None if before == 0 else (before - after) / before,
        "after_leak_cases": int(report["cases_with_sensitive_values_after"]),
        "blocked": int(report["blocked"]),
    }


def _benign_row(
    stack: DetectorStack,
    path: Path,
    dataset: dict[str, Any],
    firewall: Firewall,
) -> dict[str, Any]:
    report = firewall.evaluate(dataset["cases"])
    cases = int(report["case_count"])
    failed = int(report["failed"])
    return {
        "stack": stack.name,
        "corpus": dataset.get("name", path.stem),
        "path": str(path),
        "cases": cases,
        "passed": int(report["passed"]),
        "failed": failed,
        "specificity": None if cases == 0 else (cases - failed) / cases,
        "findings_by_family": dict(report.get("summary", {}).get("by_detector_family", {})),
    }


def format_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Comparative Protection",
        "",
        "This artifact compares LSDF detector stacks against a public PII comparator "
        "on the same bundled corpora. It is detector-normalized: every stack uses "
        "the same LSDF `broad-pii` policy/action layer, so differences below are "
        "about what each detector family finds, not about different redaction engines.",
        "",
        "## Comparator Survey",
        "",
        "| Option | Why it mattered | Decision |",
        "| --- | --- | --- |",
        "| Microsoft Presidio | OSS PII detection/de-identification SDK with analyzer, anonymizer, recognizers, NLP, pattern matching, checksums, and MIT licensing. | Measured comparator. It is the closest reproducible OSS alternative to LSDF's PII detector layer. |",
        "| Regex-only baseline | Represents the common naive detector a local agent developer can assemble quickly. | Measured baseline so LSDF's incremental value over simple patterns is visible. |",
        "| NVIDIA NeMo Guardrails | Framework with sensitive-data rails, including Presidio and GLiNER-backed flows. | Not separately measured because its PII path composes the same detector families already compared here. |",
        "| Llama Guard / Granite Guardian | Broad safety classifiers for prompts/responses and risk categories; useful guardrails, but not span-level PII anonymizers. | Surveyed only; not a fair shared-corpus PII redaction comparator without a custom policy harness. |",
        "| Lakera Guard / Cloudflare AI Security for Apps | Managed guardrail services with PII/data-leakage features. | Surveyed only; API-key service behavior is not locally reproducible from the public repo. |",
        "",
        "Sources surveyed: [Microsoft Presidio](https://microsoft.github.io/presidio/), "
        "[NVIDIA NeMo Guardrails PII detection](https://docs.nvidia.com/nemo/guardrails/latest/configure-rails/guardrail-catalog/index.html), "
        "[Meta Llama Guard 3](https://huggingface.co/meta-llama/Llama-Guard-3-1B), "
        "[IBM Granite Guardian](https://www.ibm.com/us-en/granite/docs/models/guardian), "
        "[Lakera Guard](https://docs.lakera.ai/guard), and "
        "[Cloudflare PII detection](https://developers.cloudflare.com/waf/detections/ai-security-for-apps/pii-detection/).",
        "",
        "## Method",
        "",
        f"- Policy/action layer: `{report['policy_profile']}`.",
        "- Threat corpora: "
        + ", ".join(f"`{path}`" for path in report["threat_datasets"])
        + ".",
        "- Benign corpora: "
        + ", ".join(f"`{path}`" for path in report["benign_datasets"])
        + ".",
        "- Metrics: value-level recall on threat corpora; specificity is 1 minus the benign case failure rate.",
        "- Raw-value safety: the generated report contains counts only, not sensitive fixture values.",
        "- Reproducibility: optional detector RNGs are seeded with "
        f"`{report['seed']}` before the run. GLiNER/PyTorch CPU inference can "
        "still move threshold-edge spans by a few values between independent "
        "artifact generations; compare detector stacks within this artifact, "
        "and use `EVAL.md` as the release-gate source of truth.",
        "",
    ]
    _append_threat_table(lines, report)
    _append_benign_table(lines, report)
    _append_honest_read(lines, report)
    _append_reproduce(lines)
    return "\n".join(lines).rstrip() + "\n"


def _append_threat_table(lines: list[str], report: dict[str, Any]) -> None:
    lines.extend(
        [
            "## Threat Corpus Results",
            "",
            "| Stack | Corpus | Cases | Values before | Values after | Recall | After-leak cases | Blocked |",
            "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for stack in report["stacks"]:
        if stack["status"] != "ok":
            lines.append(
                f"| `{stack['name']}` | unavailable | 0 | 0 | 0 | n/a | 0 | 0 |"
            )
            continue
        for row in stack["threats"]:
            lines.append(
                f"| `{stack['name']}` | `{row['corpus']}` | {row['cases']} | "
                f"{row['before']} | {row['after']} | {_metric(row['recall'])} | "
                f"{row['after_leak_cases']} | {row['blocked']} |"
            )
    lines.append("")


def _append_benign_table(lines: list[str], report: dict[str, Any]) -> None:
    lines.extend(
        [
            "## Benign Specificity",
            "",
            "| Stack | Corpus | Cases | Passed | Failed | Specificity | Findings by family |",
            "| --- | --- | ---: | ---: | ---: | ---: | --- |",
        ]
    )
    for stack in report["stacks"]:
        if stack["status"] != "ok":
            lines.append(
                f"| `{stack['name']}` | unavailable | 0 | 0 | 0 | n/a | {stack.get('reason', '')} |"
            )
            continue
        for row in stack["benign"]:
            findings = _family_counts(row["findings_by_family"])
            lines.append(
                f"| `{stack['name']}` | `{row['corpus']}` | {row['cases']} | "
                f"{row['passed']} | {row['failed']} | {_metric(row['specificity'])} | "
                f"{findings} |"
            )
    lines.append("")


def _append_honest_read(lines: list[str], report: dict[str, Any]) -> None:
    lines.extend(["## Honest Read", ""])
    available = [stack for stack in report["stacks"] if stack["status"] == "ok"]
    broad_pii = next(
        (stack for stack in available if stack["name"] == "lsdf_broad_pii"),
        None,
    )
    dependency_light = next(
        (stack for stack in available if stack["name"] == "lsdf_dependency_light"),
        None,
    )
    presidio = next((stack for stack in available if stack["name"] == "presidio"), None)
    if broad_pii and presidio:
        lines.append("- `lsdf_broad_pii` is the release-gated local LSDF stack in this comparison. It is the fair LSDF-vs-Presidio read for broad PII/PHI coverage.")
        loss_or_tie = False
        competitors = [
            stack
            for stack in available
            if stack["name"] in {"regex_only", "presidio"}
        ]
        for corpus in _corpus_names(report):
            lsdf_row = _row_for(broad_pii["threats"], corpus)
            if not lsdf_row:
                continue
            for competitor in competitors:
                competitor_row = _row_for(competitor["threats"], corpus)
                if not competitor_row:
                    continue
                if _recall(lsdf_row) < _recall(competitor_row):
                    loss_or_tie = True
                    lines.append(
                        f"- LSDF broad-pii loses to `{competitor['name']}` on "
                        f"`{corpus}`: {_metric(lsdf_row['recall'])} vs "
                        f"{_metric(competitor_row['recall'])}."
                    )
                elif _recall(lsdf_row) == _recall(competitor_row):
                    loss_or_tie = True
                    lines.append(
                        f"- LSDF broad-pii ties `{competitor['name']}` on "
                        f"`{corpus}` at {_metric(lsdf_row['recall'])} recall."
                    )
        if not loss_or_tie:
            lines.append("- No release-gated LSDF broad-pii threat-recall loss or tie appears against `regex_only` or `presidio` on these corpora.")
    if dependency_light:
        lines.append("- `lsdf_dependency_light` is fast and local-agent friendly, but the broad external PII corpora show where it is not the right competitor: use `broad-pii` or `broad-pii-ml` when value-level broad PII recall is the goal.")
        dependency_competitors = [
            stack
            for stack in available
            if stack["name"] in {"regex_only", "presidio"}
        ]
        for competitor in dependency_competitors:
            for corpus in _corpus_names(report):
                dep_row = _row_for(dependency_light["threats"], corpus)
                competitor_row = _row_for(competitor["threats"], corpus)
                if not dep_row or not competitor_row:
                    continue
                if _recall(dep_row) < _recall(competitor_row):
                    lines.append(
                        f"- Dependency-light LSDF loses to `{competitor['name']}` "
                        f"on `{corpus}`: {_metric(dep_row['recall'])} vs "
                        f"{_metric(competitor_row['recall'])}."
                    )
                elif _recall(dep_row) == _recall(competitor_row):
                    lines.append(
                        f"- Dependency-light LSDF ties `{competitor['name']}` on `{corpus}` "
                        f"at {_metric(dep_row['recall'])}; extra entropy/medical "
                        "detectors add no value for that corpus."
                    )
    if presidio:
        benign_rows = presidio.get("benign", [])
        if any(_recall({"recall": row.get("specificity")}) < 0.95 for row in benign_rows):
            lines.append("- Presidio also produced benign false positives in this run, so using it as a drop-in default would require threshold or recognizer tuning before enforcement.")
    lines.append("- Presidio remains the strongest public OSS comparator for standalone PII detection. LSDF's differentiator is cross-surface OpenAI-compatible enforcement: messages, RAG, tool results, tool-call arguments, reasoning, traces, and logs share one policy/action layer.")
    lines.append("")


def _append_reproduce(lines: list[str]) -> None:
    lines.extend(
        [
            "## Reproduce",
            "",
            "Run from the public repo root with the optional detector image available:",
            "",
            "```bash",
            "docker compose --profile optional run --rm --entrypoint python optional-cli \\",
            "  scripts/build_comparative_protection.py \\",
            "  --output docs/comparative-protection.md \\",
            "  --seed 0",
            "```",
            "",
            "For a single-corpus direct comparison table, use the existing CLI rather than a new command:",
            "",
            "```bash",
            "docker compose --profile optional run --rm optional-cli compare-detectors \\",
            "  evals/br_agentic_pii.json \\",
            "  --profile broad-pii \\",
            "  --set regex_only=regex \\",
            "  --set presidio=presidio \\",
            "  --set lsdf_dependency_light=regex,entropy,medical-regex,contextual-anchored \\",
            "  --set lsdf_broad_pii=regex,entropy,medical-regex,contextual-anchored,contextual-broad,gliner \\",
            "  --format markdown",
            "```",
            "",
        ]
    )


def _read_dataset(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _corpus_names(report: dict[str, Any]) -> list[str]:
    names: list[str] = []
    for stack in report["stacks"]:
        for row in stack.get("threats", []):
            if row["corpus"] not in names:
                names.append(row["corpus"])
    return names


def _row_for(rows: list[dict[str, Any]], corpus: str) -> dict[str, Any] | None:
    return next((row for row in rows if row["corpus"] == corpus), None)


def _recall(row: dict[str, Any]) -> float:
    return float(row.get("recall") or 0.0)


def _metric(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.3f}"


def _family_counts(counts: dict[str, int]) -> str:
    if not counts:
        return "_none_"
    return ", ".join(f"{family}={count}" for family, count in sorted(counts.items()))


def _seed_optional_detectors(seed: int) -> None:
    random.seed(seed)
    try:  # pragma: no cover - optional dependency.
        import numpy

        numpy.random.seed(seed)
    except Exception:
        pass
    try:  # pragma: no cover - optional dependency.
        import torch

        torch.manual_seed(seed)
        try:
            torch.use_deterministic_algorithms(True, warn_only=True)
        except TypeError:
            torch.use_deterministic_algorithms(True)
    except Exception:
        pass


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("docs/comparative-protection.md"),
    )
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    args = parser.parse_args()

    report = build_report(seed=args.seed)
    if str(args.output) == "-":
        print(format_markdown(report), end="")
        return 0
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(format_markdown(report), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
