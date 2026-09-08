# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

from .comparison import DetectorSet, compare_detector_sets, parse_detector_set
from .detectors import DetectorProviders
from .policy import Policy
from .reporting import format_detector_comparison_markdown
from .scanners.openai_privacy_filter import (
    build_installed_openai_privacy_filter_detector,
)
from .scanners.presidio import build_installed_presidio_detector
from .surfaces import Surface

OPTIONAL_ARTIFACT_DETECTOR_SETS = (
    "presidio=presidio",
    "privacy=openai_privacy_filter",
    "default_optional=regex,entropy,medical-regex,contextual-anchored,presidio,openai_privacy_filter",
)
DEFAULT_OPTIONAL_ARTIFACT_DATASETS = (
    Path("evals/safety_matrix.json"),
    Path("evals/utility_matrix.json"),
    Path("evals/observability_matrix.json"),
)
DEFAULT_OPTIONAL_ARTIFACT_ROOT = Path("docs/artifacts/optional-detectors")


@dataclass(frozen=True)
class OptionalDetectorArtifactResult:
    output_dir: Path
    manifest: dict[str, Any]


def default_optional_artifact_output_dir() -> Path:
    return DEFAULT_OPTIONAL_ARTIFACT_ROOT / date.today().isoformat()


def optional_artifact_detector_sets() -> list[DetectorSet]:
    return [parse_detector_set(value) for value in OPTIONAL_ARTIFACT_DETECTOR_SETS]


def write_optional_detector_artifacts(
    *,
    policy: Policy,
    output_dir: Path | None = None,
    dataset_paths: list[Path] | None = None,
    detector_providers: DetectorProviders | None = None,
    detector_status: dict[str, Any] | None = None,
) -> OptionalDetectorArtifactResult:
    output_dir = output_dir or default_optional_artifact_output_dir()
    dataset_paths = dataset_paths or list(DEFAULT_OPTIONAL_ARTIFACT_DATASETS)
    output_dir.mkdir(parents=True, exist_ok=True)

    providers = dict(detector_providers or {})
    status = dict(detector_status or {})
    if detector_providers is None:
        providers, status = build_optional_detector_providers()

    reports = []
    for dataset_path in dataset_paths:
        dataset = _read_json(dataset_path)
        report = compare_detector_sets(
            policy=policy,
            dataset=dataset,
            dataset_path=dataset_path,
            detector_sets=optional_artifact_detector_sets(),
            detector_providers=providers,
        )
        slug = _dataset_slug(dataset, dataset_path)
        json_path = output_dir / f"{slug}.comparison.json"
        markdown_path = output_dir / f"{slug}.comparison.md"
        json_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        markdown_path.write_text(
            format_detector_comparison_markdown(report),
            encoding="utf-8",
        )
        reports.append(
            {
                "dataset": report["dataset"],
                "json": str(json_path),
                "markdown": str(markdown_path),
                "detector_sets": [
                    {
                        "name": result.get("name"),
                        "status": result.get("status"),
                        "reason": result.get("reason"),
                        "passed": result.get("passed", 0),
                        "failed": result.get("failed", 0),
                    }
                    for result in report.get("detector_sets", [])
                ],
            }
        )

    manifest = {
        "artifact_type": "optional-detector-dependency-diagnostic",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "profile": policy.name,
        "mode": policy.mode,
        "output_dir": str(output_dir),
        "datasets": [str(path) for path in dataset_paths],
        "detector_sets": list(OPTIONAL_ARTIFACT_DETECTOR_SETS),
        "optional_detector_status": status,
        "reports": reports,
        "raw_value_policy": "raw sensitive values are redacted; reveal mode is not used",
    }
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n",
        encoding="utf-8",
    )
    (output_dir / "operational-notes.md").write_text(
        format_optional_detector_operational_notes(manifest),
        encoding="utf-8",
    )
    return OptionalDetectorArtifactResult(output_dir=output_dir, manifest=manifest)


def build_optional_detector_providers() -> tuple[dict[str, Any], dict[str, Any]]:
    providers: dict[str, Any] = {}
    status: dict[str, Any] = {}

    try:
        presidio = build_installed_presidio_detector()
    except RuntimeError as exc:
        status["presidio"] = {"status": "unavailable", "reason": str(exc)}
    else:
        providers["presidio"] = presidio
        status["presidio"] = _probe_detector(
            presidio,
            "Alice Smith can be reached at dev@example.test or +1 202-555-0199.",
        )

    try:
        privacy_filter = build_installed_openai_privacy_filter_detector()
    except RuntimeError as exc:
        status["openai_privacy_filter"] = {
            "status": "unavailable",
            "reason": str(exc),
        }
    else:
        providers["openai_privacy_filter"] = privacy_filter
        status["openai_privacy_filter"] = _probe_detector(
            privacy_filter,
            "Contact Alice Smith at dev@example.test. The secret is api_LSDF_OPTIONAL_SMOKE_TOKEN.",
        )
        if privacy_filter.provider_metadata:
            status["openai_privacy_filter"]["provider"] = dict(
                privacy_filter.provider_metadata
            )

    return providers, status


def format_optional_detector_operational_notes(manifest: dict[str, Any]) -> str:
    lines = [
        "# Optional Detector Dependency Diagnostic Artifacts",
        "",
        f"- Generated at: {manifest['generated_at']}",
        f"- Profile: {manifest['profile']}",
        f"- Mode: {manifest['mode']}",
        f"- Output directory: {manifest['output_dir']}",
        "- Raw-value policy: raw sensitive values are redacted; reveal mode is not used",
        "",
        "## Local Setup",
        "",
        "Build and run optional detector diagnostics only through Docker Compose:",
        "",
        "```bash",
        "docker compose --profile optional build optional-test",
        "LSDF_OPENAI_PRIVACY_FILTER_MODEL=openai/privacy-filter \\",
        "LSDF_OPENAI_PRIVACY_FILTER_LOCAL_FILES_ONLY=true \\",
        "LSDF_RUN_OPTIONAL_DETECTOR_BATTERY_SMOKE=1 \\",
        "  docker compose --profile optional run --rm optional-test",
        "LSDF_REQUIRE_OPENAI_PRIVACY_FILTER=1 \\",
        "  docker compose --profile optional run --rm optional-test",
        "docker compose --profile optional run --rm optional-cli optional-detector-artifacts --output-dir docs/artifacts/optional-detectors/optional-run",
        "```",
        "",
        "The privacy-filter path defaults to local cache only. Use the Docker-managed Hugging Face cache volume; if the model is not cached, the diagnostic artifact records a safe unavailable reason instead of downloading by default. The required smoke command should pass only when a release runner has a prepared privacy-filter cache.",
        "",
        "## Optional Detector Status",
        "",
    ]
    for family, status in manifest["optional_detector_status"].items():
        lines.append(f"- `{family}`: {status.get('status', 'unknown')}")
        if status.get("reason"):
            lines.append(f"  - Reason: {status['reason']}")
        if status.get("finding_count") is not None:
            lines.append(f"  - Smoke findings: {status.get('finding_count', 0)}")
        if status.get("entities"):
            lines.append(f"  - Smoke entities: {', '.join(status['entities'])}")
        provider = status.get("provider")
        if provider:
            lines.append(f"  - Provider: {provider.get('implementation', 'unknown')}")
            lines.append(f"  - Model: {provider.get('model_name', 'unknown')}")
            if "load_seconds" in provider:
                lines.append(f"  - Load seconds: {provider['load_seconds']}")
            if "parameter_count" in provider:
                lines.append(f"  - Parameter count: {provider['parameter_count']}")
    lines.extend(["", "## Reports", ""])
    for report in manifest["reports"]:
        lines.append(f"- {report['dataset']}")
        lines.append(f"  - JSON: `{report['json']}`")
        lines.append(f"  - Markdown: `{report['markdown']}`")
    return "\n".join(lines).rstrip() + "\n"


def _probe_detector(detector: Any, value: str) -> dict[str, Any]:
    surface = Surface("output.content", ("content",), value)
    findings = detector.scan(surface)
    metadata_keys = sorted(
        {key for finding in findings for key in (finding.metadata or {}).keys()}
    )
    return {
        "status": "available",
        "detector_id": detector.detector_id,
        "detector_family": detector.detector_family,
        "finding_count": len(findings),
        "entities": sorted({finding.entity for finding in findings}),
        "detector_ids": sorted({finding.detector_id for finding in findings}),
        "metadata_keys": metadata_keys,
    }


def _dataset_slug(dataset: dict[str, Any], path: Path) -> str:
    name = str(dataset.get("name") or path.stem)
    return "".join(char if char.isalnum() or char in "._-" else "-" for char in name)


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))
