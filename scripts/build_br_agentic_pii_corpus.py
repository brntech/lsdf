"""Build evals/br_agentic_pii.json from guardion/BR-Agentic-PII-Benchmark.

Source: https://huggingface.co/datasets/guardion/BR-Agentic-PII-Benchmark
(MIT; fully synthetic Brazilian Portuguese banking-agent conversations).

The committed `evals/br_agentic_pii.json` uses the customer-registration
scenario slice. It adds Portuguese agentic tool-use coverage without pulling
in the source corpus's financial-value labels, which LSDF does not currently
treat as release-gated PII.

By default this script rewrites or copies the committed snapshot without
network access:

    docker compose run --rm python scripts/build_br_agentic_pii_corpus.py \
        --output evals/br_agentic_pii.json

To rebuild from the upstream corpus, pass either `--input path/to/dataset.jsonl`
or the network-opt-in `--fetch-upstream` flag.
"""

from __future__ import annotations

import argparse
import json
import urllib.request
from pathlib import Path
from typing import Any

SOURCE_URL = (
    "https://huggingface.co/datasets/guardion/BR-Agentic-PII-Benchmark/"
    "resolve/main/dataset.jsonl"
)
DEFAULT_SNAPSHOT_PATH = Path("evals/br_agentic_pii.json")

BR_AGENTIC_TO_LSDF = {
    "PERSON_NAME": "PERSON",
    "CPF": "BR_CPF",
    "PHONE_NUMBER": "PHONE",
    "EMAIL": "EMAIL",
    "STREET_ADDRESS": "ADDRESS",
    "BANK_ACCOUNT": "BANK_ACCOUNT",
    "CREDIT_CARD": "CREDIT_CARD",
}

DEFAULT_SCENARIOS = ("atualizacao_cadastral",)

CATEGORY_PRIORITY = (
    ("financial", {"CREDIT_CARD", "BANK_ACCOUNT"}),
    ("pii", {"PERSON", "EMAIL", "PHONE", "BR_CPF", "ADDRESS"}),
)


def load_rows(
    input_path: Path | None,
    source_url: str,
    *,
    fetch_upstream: bool = False,
) -> list[dict[str, Any]]:
    if input_path is not None:
        raw = input_path.read_text(encoding="utf-8")
    elif fetch_upstream:
        with urllib.request.urlopen(source_url, timeout=30) as response:
            raw = response.read().decode("utf-8")
    else:
        raise ValueError("pass --input or --fetch-upstream to rebuild from source rows")
    return [json.loads(line) for line in raw.splitlines() if line.strip()]


def load_committed_snapshot(snapshot_path: Path) -> dict[str, Any]:
    return json.loads(snapshot_path.read_text(encoding="utf-8"))


def to_case(row: dict[str, Any]) -> dict[str, Any] | None:
    messages = [_message_without_spans(message) for message in row["messages"]]
    spans = [
        span
        for message in row["messages"]
        for span in message.get("pii_spans", [])
        if span.get("text") not in ("", None)
    ]
    if not spans:
        return None
    labels = sorted({str(span["label"]) for span in spans})
    expected_entities = _lsdf_entities(labels)
    sensitive_values = sorted({str(span["text"]) for span in spans})
    case: dict[str, Any] = {
        "id": f"br-agentic-pii-{row['conversation_id']}",
        "category": _categorize(expected_entities),
        "surface": "input.messages",
        "payload": {"messages": messages},
        "sensitive_values": sensitive_values,
        "expected_entities": expected_entities,
        "expected_surfaces": _expected_surfaces(row),
        "expected_absent": sensitive_values,
        "br_agentic_labels": labels,
        "scenario": row["scenario"],
        "language": "Portuguese",
        "locale": "pt_BR",
    }
    unmapped = [label for label in labels if label not in BR_AGENTIC_TO_LSDF]
    if unmapped:
        case["known_gap_labels"] = unmapped
    return case


def _message_without_spans(message: dict[str, Any]) -> dict[str, Any]:
    clean = {
        key: value
        for key, value in message.items()
        if key not in {"pii_spans"}
    }
    return clean


def _lsdf_entities(labels: list[str]) -> list[str]:
    seen: list[str] = []
    for label in labels:
        entity = BR_AGENTIC_TO_LSDF.get(label)
        if entity and entity not in seen:
            seen.append(entity)
    return seen


def _categorize(entities: list[str]) -> str:
    entity_set = set(entities)
    for category, labels in CATEGORY_PRIORITY:
        if entity_set & labels:
            return category
    return "other"


def _expected_surfaces(row: dict[str, Any]) -> list[str]:
    surfaces: set[str] = set()
    for message in row.get("messages", []):
        role = message.get("role")
        for span in message.get("pii_spans", []):
            field_type = span.get("field_type")
            if field_type == "tool_argument":
                surfaces.add("output.tool_calls.arguments")
            elif field_type == "tool_result" or role == "tool":
                surfaces.add("input.tool_results")
            elif field_type == "text_content":
                surfaces.add("input.tool_results" if role == "tool" else "input.messages")
    order = ("input.messages", "input.tool_results", "output.tool_calls.arguments")
    return [surface for surface in order if surface in surfaces]


def build_corpus(
    rows: list[dict[str, Any]],
    *,
    scenarios: tuple[str, ...],
) -> dict[str, Any]:
    cases = [
        case
        for row in rows
        if row.get("scenario") in scenarios
        for case in [to_case(row)]
        if case is not None
    ]
    by_label = _count_labels(cases)
    by_surface = _count_surfaces(cases)
    return {
        "name": "br_agentic_pii",
        "version": "0.1",
        "source": "guardion/BR-Agentic-PII-Benchmark",
        "source_license": "MIT",
        "source_url": "https://huggingface.co/datasets/guardion/BR-Agentic-PII-Benchmark",
        "description": (
            "MIT-licensed synthetic Brazilian Portuguese banking-agent PII "
            "corpus. This committed sample uses the customer-registration "
            "scenario slice from BR-Agentic-PII-Benchmark because it adds "
            "agentic OpenAI-style messages, tool arguments, and tool-result "
            "coverage without the larger PIIBench composite-license burden "
            "or the financial-value labels LSDF does not release-gate today. "
            "Default builder invocation rewrites this committed snapshot; "
            "pass `--fetch-upstream` or `--input` to rebuild from source JSONL."
        ),
        "selection_note": (
            "Surveyed PIIBench, HiveTrace PII-Bench (ru), ai4privacy PHI, and "
            "BR-Agentic-PII-Benchmark. BR-Agentic was selected because it is "
            "small, MIT-licensed, fully synthetic, Portuguese, and explicitly "
            "models agent tool arguments/results; PIIBench overlaps existing "
            "ai4privacy/Nemotron sources and carries constituent-license "
            "complexity, while HiveTrace is access-gated/evaluation-only and "
            "ai4privacy PHI overlaps the existing medical_phi_replay focus."
        ),
        "scenarios": list(scenarios),
        "language": "Portuguese",
        "locale": "pt_BR",
        "case_count": len(cases),
        "by_source_label_count": by_label,
        "by_surface_count": by_surface,
        "cases": cases,
    }


def _count_labels(cases: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for case in cases:
        for label in case.get("br_agentic_labels", []):
            counts[label] = counts.get(label, 0) + 1
    return dict(sorted(counts.items()))


def _count_surfaces(cases: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for case in cases:
        for surface in case.get("expected_surfaces", []):
            counts[surface] = counts.get(surface, 0) + 1
    return dict(sorted(counts.items()))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, default=None)
    parser.add_argument(
        "--fetch-upstream",
        action="store_true",
        help="Fetch the upstream Hugging Face JSONL. Network access is opt-in.",
    )
    parser.add_argument(
        "--snapshot",
        type=Path,
        default=DEFAULT_SNAPSHOT_PATH,
        help="Committed LSDF snapshot used when --input/--fetch-upstream are omitted.",
    )
    parser.add_argument("--source-url", default=SOURCE_URL)
    parser.add_argument("--output", type=Path, default=DEFAULT_SNAPSHOT_PATH)
    parser.add_argument(
        "--scenario",
        dest="scenarios",
        action="append",
        default=None,
        help="Scenario identifier to include. Repeatable.",
    )
    args = parser.parse_args(argv)
    scenarios = tuple(args.scenarios or DEFAULT_SCENARIOS)
    if args.scenarios and args.input is None and not args.fetch_upstream:
        parser.error("--scenario only applies with --input or --fetch-upstream")

    if args.input is None and not args.fetch_upstream:
        corpus = load_committed_snapshot(args.snapshot)
    else:
        rows = load_rows(
            args.input,
            args.source_url,
            fetch_upstream=args.fetch_upstream,
        )
        corpus = build_corpus(rows, scenarios=scenarios)
    if not corpus["cases"]:
        raise SystemExit(f"No cases matched scenarios: {', '.join(scenarios)}")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(corpus, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
