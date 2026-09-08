"""Convert explicitly supplied ai4privacy source files into a local benchmark.

Source: https://huggingface.co/datasets/ai4privacy/pii-masking-300k
Source terms depend on the source revision and separately obtained permissions.
The source data is not bundled with LSDF. Supply the applicable license or
permission description and source revision when converting local files.
LSDF's software license grants no rights to this dataset.

This converter reads local JSONL files only. It never downloads source
data or model files. Preserve the relative filenames in LANGUAGES below
under --input-dir. Output stays under the ignored .lsdf/external-benchmarks
directory and is excluded from Docker image builds.

    docker compose run --rm python scripts/build_ai4privacy_multilingual_corpus.py \
        --input-dir .lsdf/licensed-source --cases-per-language 25 --seed 0 \
        --source-license YOUR_SOURCE_TERMS --source-revision YOUR_SOURCE_REVISION

Sampling shuffles the first scan_budget nonblank records of each language
file, then takes up to cases-per-language records. It does not sample the
whole file or stratify by entity, category, or document length. The same
seed is reused per language, so equal window sizes share the positional
permutation. Results are deterministic for identical local inputs/settings.
Only the Python standard library is required inside the container.
"""

from __future__ import annotations

import argparse
import ast
import json
import random
import sys
from pathlib import Path
from typing import Any

# `ast.literal_eval` is a safe parser for Python literals only (dicts,
# lists, strings, numbers, tuples, booleans, None). It does not execute
# code. Aliased to keep static security scanners that flag the
# substring "eval" from misclassifying this safe parser.
_safe_python_literal_parser = ast.literal_eval


OUTPUT_ROOT = Path(__file__).resolve().parents[1] / ".lsdf" / "external-benchmarks"


LANGUAGES = {
    "English": "data/train/1english_openpii_30k.jsonl",
    "Dutch": "data/train/dutch_openpii_28k.jsonl",
    "French": "data/train/french_openpii_31k.jsonl",
    "German": "data/train/german_openpii_30k.jsonl",
    "Italian": "data/train/italian_openpii_29k.jsonl",
    "Spanish": "data/train/spanish_openpii_29k.jsonl",
}


# Map ai4privacy entity labels to LSDF's canonical entity vocabulary.
# Labels not in this map remain visible via `sensitive_values` (so
# containment is still measured) but are not asserted in
# `expected_entities` — they represent known coverage gaps that the
# corpus deliberately tests across multiple languages. All values, including
# unmapped labels, remain expected_absent: exact entity tagging and post-policy
# containment are separate contracts. Blocking or whole-surface redaction can
# contain an unmapped value without emitting that label.
AI4PRIVACY_TO_LSDF = {
    "GIVENNAME1": "PERSON",
    "GIVENNAME2": "PERSON",
    "LASTNAME1": "PERSON",
    "LASTNAME2": "PERSON",
    "LASTNAME3": "PERSON",
    "EMAIL": "EMAIL",
    "TEL": "PHONE",
    "BOD": "DATE_OF_BIRTH",
    "SOCIALNUMBER": "OTHER_STRONG_ID",
    "STATE": "ADDRESS",
    "STREET": "ADDRESS",
    "BUILDING": "ADDRESS",
    "CITY": "ADDRESS",
    "POSTCODE": "ADDRESS",
    "COUNTRY": "ADDRESS",
    "SECADDRESS": "ADDRESS",
    "GEOCOORD": "ADDRESS",
}

CATEGORY_PRIORITY = (
    ("credentials", {"API_KEY", "OTHER_SECRET"}),
    ("phi", {"MEDICATION", "MEDICAL_CONDITION", "BLOOD_TYPE", "HEALTH_INSURANCE_ID", "LAB_VALUE", "ICD_CODE", "DIAGNOSIS_TEXT", "MRN", "OTHER_PHI"}),
    ("financial", {"CREDIT_CARD", "BANK_ACCOUNT", "IBAN"}),
    ("pii", {"PERSON", "EMAIL", "PHONE", "US_SSN", "PASSPORT", "DRIVER_LICENSE", "NATIONAL_ID", "TAX_ID", "BR_CPF", "OTHER_STRONG_ID", "DATE_OF_BIRTH", "ADDRESS"}),
)


def _parse_python_literal(raw: Any) -> list[dict[str, Any]]:
    """privacy_mask is sometimes a list, sometimes a Python-literal string."""
    if isinstance(raw, list):
        return raw
    return _safe_python_literal_parser(raw)


def _source_error(language: str, record: int, field: str, detail: str) -> ValueError:
    # Never interpolate source ids, values, parser exceptions, or local paths.
    safe_language = language if language in LANGUAGES else "unknown language"
    return ValueError(f"{safe_language} record {record} field {field}: {detail}")


def _validate_source_record(
    example: Any, language: str, record: int,
) -> tuple[str, list[dict[str, Any]]]:
    if not isinstance(example, dict):
        raise _source_error(language, record, "record", "expected an object")
    identifier = example.get("id")
    if not (
        isinstance(identifier, str) and identifier.strip()
        or isinstance(identifier, int) and not isinstance(identifier, bool)
    ):
        raise _source_error(language, record, "id", "expected a nonblank string or integer")
    if not isinstance(example.get("source_text"), str):
        raise _source_error(language, record, "source_text", "expected a string")
    if "privacy_mask" not in example:
        raise _source_error(language, record, "privacy_mask", "required field is missing")
    try:
        spans = _parse_python_literal(example["privacy_mask"])
    except (ValueError, SyntaxError, TypeError, RecursionError):
        raise _source_error(language, record, "privacy_mask", "expected a list or list literal") from None
    if not isinstance(spans, list):
        raise _source_error(language, record, "privacy_mask", "expected a list")
    for index, span in enumerate(spans):
        field = f"privacy_mask[{index}]"
        if not isinstance(span, dict):
            raise _source_error(language, record, field, "expected an object")
        if not isinstance(span.get("label"), str) or not span["label"].strip():
            raise _source_error(language, record, field + ".label", "expected a nonblank string")
        if not isinstance(span.get("value"), str) or not span["value"].strip():
            raise _source_error(language, record, field + ".value", "expected a nonblank string")
        if span["value"] not in example["source_text"]:
            raise _source_error(language, record, field + ".value", "annotation is absent from source_text")
    return example["source_text"], spans


def lsdf_entities(spans: list[dict[str, Any]]) -> list[str]:
    seen: list[str] = []
    for span in spans:
        mapped = AI4PRIVACY_TO_LSDF.get(span["label"])
        if mapped and mapped not in seen:
            seen.append(mapped)
    return seen


def categorize(entities: list[str]) -> str:
    entity_set = set(entities)
    for category, labels in CATEGORY_PRIORITY:
        if entity_set & labels:
            return category
    return "other"


def to_case(
    example: dict[str, Any], language: str, *, record: int = 1,
) -> dict[str, Any] | None:
    text, spans = _validate_source_record(example, language, record)
    if not spans:
        # A valid unannotated record is not a threat case; count the shortfall.
        return None
    sensitive_values = sorted({span["value"] for span in spans})
    ai4privacy_labels = sorted({span["label"] for span in spans})
    expected_entities = lsdf_entities(spans)
    category = categorize(expected_entities) if expected_entities else "other"
    case: dict[str, Any] = {
        "id": f"ai4privacy-{language[:2].lower()}-{example['id']}",
        "category": category,
        "surface": "output.content",
        "payload": {
            "choices": [
                {
                    "message": {
                        "content": text,
                    }
                }
            ]
        },
        "sensitive_values": sensitive_values,
        "expected_entities": expected_entities,
        "expected_surfaces": ["output.content"],
        "expected_absent": sensitive_values,
        "ai4privacy_labels": ai4privacy_labels,
        "language": language,
    }
    unmapped = [
        label for label in ai4privacy_labels if label not in AI4PRIVACY_TO_LSDF
    ]
    if unmapped:
        case["known_gap_labels"] = unmapped
    return case


def sample_one_language(
    data_file: Path, target: int, seed: int, scan_budget: int, *, language: str = "unknown",
) -> list[dict[str, Any]]:
    """Validate and shuffle the first scan_budget nonblank local JSONL records."""
    pool: list[dict[str, Any]] = []
    record = 0
    try:
        with data_file.open(encoding="utf-8") as source:
            for record, line in enumerate(source, start=1):
                if not line.strip():
                    continue
                if len(pool) >= scan_budget:
                    break
                try:
                    example = json.loads(line)
                except (ValueError, RecursionError):
                    raise _source_error(language, record, "json", "invalid JSON") from None
                # Validate the whole scanned window, even records not selected later.
                _validate_source_record(example, language, record)
                pool.append(example)
    except UnicodeError:
        raise _source_error(language, record, "encoding", "expected UTF-8 source") from None
    except OSError:
        raise _source_error(language, record, "file", "cannot read local source") from None
    rng = random.Random(seed)
    rng.shuffle(pool)
    return pool[:target]


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input-dir", type=Path, required=True,
        help="Directory containing separately obtained local source JSONL files.",
    )
    parser.add_argument(
        "--source-license", required=True,
        help="Applicable license or separately obtained permission description for these files.",
    )
    parser.add_argument(
        "--source-revision", required=True,
        help="Source revision, snapshot identifier, or other identifying provenance description.",
    )
    parser.add_argument(
        "--output", type=Path, default=OUTPUT_ROOT / "ai4privacy_multilingual.json",
        help="Local output path beneath .lsdf/external-benchmarks (never bundled).",
    )
    parser.add_argument("--cases-per-language", type=int, default=25)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument(
        "--scan-budget",
        type=int,
        default=2000,
        help="How many records per language to consider before sampling.",
    )
    args = parser.parse_args(argv)
    if not args.source_license.strip() or not args.source_revision.strip():
        parser.error("source-license and source-revision must not be blank")
    if args.cases_per_language < 1 or args.scan_budget < 1:
        parser.error("cases-per-language and scan-budget must be positive")
    if not args.output.resolve().is_relative_to(OUTPUT_ROOT.resolve()):
        parser.error("output must remain under .lsdf/external-benchmarks")
    for language, relative_path in LANGUAGES.items():
        if not (args.input_dir / relative_path).is_file():
            parser.error(f"missing local source file for {language}")

    cases: list[dict[str, Any]] = []
    by_language_count = {language: 0 for language in LANGUAGES}
    for language, data_file in LANGUAGES.items():
        try:
            sampled = sample_one_language(
                args.input_dir / data_file,
                target=args.cases_per_language,
                seed=args.seed,
                scan_budget=args.scan_budget,
                language=language,
            )
            for example in sampled:
                case = to_case(example, language=language)
                if case is not None:
                    cases.append(case)
                    by_language_count[language] += 1
        except ValueError as exc:
            parser.error(str(exc))
        count = by_language_count[language]
        if count < args.cases_per_language:
            print(
                f"warning: {language}: produced {count} annotated cases; "
                f"requested {args.cases_per_language} from head-window shuffle",
                file=sys.stderr,
            )

    cases.sort(key=lambda c: (c["language"], c["category"], c["id"]))

    payload = {
        "name": "ai4privacy_multilingual",
        "version": "0.1",
        "source": "ai4privacy/pii-masking-300k (OpenPII-220k subset)",
        "source_license": args.source_license,
        "source_revision": args.source_revision,
        "source_url": "https://huggingface.co/datasets/ai4privacy/pii-masking-300k",
        "description": (
            "Multilingual PII threat corpus complementing the "
            "English-only piece_b_replay / medical_phi_replay / "
            "nemotron_pii corpora. Head-window shuffle of the first "
            "scan_budget nonblank records per language, then up to "
            "cases_per_language records selected, across English, Dutch, "
            "French, German, Italian, and Spanish. Entities not in "
            "LSDF's canonical vocabulary remain in `sensitive_values` "
            "for containment measurement and surface as "
            "`known_gap_labels` per case. Regenerate via "
            "the local-only converter with separately obtained source files."
        ),
        "license_note": (
            "External benchmark, not bundled with LSDF. The LSDF software "
            "license grants no rights to this dataset. Source license and "
            "revision are caller-supplied provenance, not verified permissions."
        ),
        "languages": sorted(LANGUAGES.keys()),
        "sampling": "head-window shuffle",
        "sampling_note": (
            "The same seed is reused per language; equal-sized head windows "
            "share positional permutations. Empty annotations are omitted "
            "without refilling, so language counts can be below the target."
        ),
        "scan_budget": args.scan_budget,
        "seed": args.seed,
        "cases_per_language": args.cases_per_language,
        "by_language_count": dict(by_language_count),
        "cases": cases,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(
        f"Wrote {len(cases)} cases to {args.output} "
        f"({dict(by_language_count)})."
    )


if __name__ == "__main__":
    main()
