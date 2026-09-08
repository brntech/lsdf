# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import argparse
import json
from copy import deepcopy
from pathlib import Path
from typing import Any

BATTERY_FILENAMES = {
    "matrix": "safety_matrix.json",
    "utility": "utility_matrix.json",
    "observability": "observability_matrix.json",
}

SURFACES = [
    "input.messages",
    "input.rag_context",
    "input.tool_results",
    "output.content",
    "output.reasoning",
    "output.tool_calls.arguments",
    "logs.traces",
]

INPUT_SURFACES = {"input.messages", "input.rag_context", "input.tool_results"}
SECRET_ENTITIES = {
    "API_KEY",
    "AWS_KEY",
    "AZURE_KEY",
    "DATADOG_KEY",
    "JWT",
    "BEARER_TOKEN",
    "DATABASE_URL",
    "PEM_BLOCK",
    "PRIVATE_KEY",
    "OTHER_SECRET",
}
HARD_IDENTIFIER_ENTITIES = {"US_SSN", "MRN", "MEDICATION", "CREDIT_CARD", "IBAN"}
LOW_NOISE_ENTITIES = {"EMAIL", "PHONE"}

ENTITY_SAMPLES = {
    "API_KEY": [
        "api_fixture0000000001",
        "sk_fixture0000000002",
        "api_LSDF_FIXTURE_EVAL_000003",
        "token-fixture0000000004",
    ],
    "OTHER_SECRET": [
        "R3d1s_Pr0d_2024!Secure",
        "VaultSync_2026!Key",
        "Pgr_Bkup_77#Rotate_2026",
        "N0deCache_77!Rotate",
    ],
    "US_SSN": [
        "000-00-0000",
        "987-65-4321",
        "111-22-3333",
        "222-33-4444",
    ],
    "MRN": [
        "MRN: LSDF-FIXTURE-00001",
        "MRN: B77889",
        "MRN: C99887",
        "MRN# Z44556",
    ],
    "MEDICATION": [
        "metformin 500mg",
        "lisinopril 10mg",
        "atorvastatin 20mg",
        "warfarin 2mg",
    ],
    "CREDIT_CARD": [
        "4111 1111 1111 1111",
        "4242 4242 4242 4242",
        "5555 5555 5555 4444",
        "378282246310005",
    ],
    "IBAN": [
        "GB82WEST12345698765432",
        "DE89370400440532013000",
        "FR1420041010050500013M02606",
        "ES9121000418450200051332",
    ],
    "EMAIL": [
        "jane.patient@example.com",
        "ops.owner@example.org",
        "local.builder@example.net",
        "support.alias@example.io",
    ],
    "PHONE": [
        "(555) 010-2020",
        "555-010-3030",
        "+1 555 010 4040",
        "555.010.5050",
    ],
}

DETECTOR_EXPECTATIONS = {
    "API_KEY": ("regex.api_key", "regex"),
    "OTHER_SECRET": ("entropy.secret", "entropy"),
    "US_SSN": ("regex.ssn", "regex"),
    "MRN": ("regex.mrn", "regex"),
    "MEDICATION": ("medical-regex.phi_pattern", "medical-regex"),
    "CREDIT_CARD": ("regex.credit_card_luhn", "regex"),
    "IBAN": ("regex.iban", "regex"),
    "EMAIL": ("regex.email", "regex"),
    "PHONE": ("regex.phone", "regex"),
}

KNOWN_GAPS = [
    (
        "person-detector",
        "known-gap-person",
        ["Lisa Nakamura"],
        "Lisa Nakamura approved the internal memo for review",
    ),
    (
        "address-detector",
        "known-gap-address",
        ["742 Evergreen Terrace"],
        "Ship the file to 742 Evergreen Terrace after approval",
    ),
    (
        "date-of-birth-detector",
        "known-gap-dob",
        ["1974-05-13"],
        "The patient DOB is 1974-05-13 in the intake note",
    ),
    (
        "bank-routing-account",
        "known-gap-financial",
        ["021000021", "000123456789"],
        "Use routing 021000021 with account 000123456789 for the transfer",
    ),
    (
        "person-salary-association",
        "known-gap-contextual-dlp",
        ["Priya Sundaram", "$210,000"],
        "Priya Sundaram's compensation is $210,000 for the new role",
    ),
    (
        "customer-account-association",
        "known-gap-contextual-business",
        ["Acme", "CUST-44219", "confidential renewal terms"],
        "Acme customer account CUST-44219 has confidential renewal terms",
    ),
    (
        "patient-diagnosis-association",
        "known-gap-contextual-phi",
        ["Mateo Chen", "hypertension"],
        "Mateo Chen is associated with hypertension in the care note",
    ),
]


def build_safety_matrix() -> dict[str, Any]:
    """Build the deterministic bundled evaluation safety proof matrix."""

    return _dataset(
        name="safety_matrix",
        description=(
            "Public LSDF safety matrix. Known-gap cases are "
            "measured as would-fail without failing the dataset."
        ),
        cases=_build_matrix_cases(),
    )


def build_utility_matrix() -> dict[str, Any]:
    """Build the deterministic bundled evaluation utility and false-positive battery."""

    return _dataset(
        name="utility_matrix",
        description=(
            "Benign utility and false-positive battery for dependency-light LSDF defaults."
        ),
        cases=_build_utility_cases(),
    )


def build_observability_matrix() -> dict[str, Any]:
    """Build the deterministic bundled evaluation observability leak battery."""

    return _dataset(
        name="observability_matrix",
        description=(
            "Reasoning, tool-call, trace, log, and transcript-style leak battery."
        ),
        cases=_build_observability_cases(),
    )


def build_eval_batteries(battery: str = "all") -> dict[str, dict[str, Any]]:
    builders = {
        "matrix": build_safety_matrix,
        "utility": build_utility_matrix,
        "observability": build_observability_matrix,
    }
    if battery == "all":
        return {name: builder() for name, builder in builders.items()}
    if battery not in builders:
        raise ValueError(f"Unknown battery: {battery}")
    return {battery: builders[battery]()}


def _dataset(name: str, description: str, cases: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "name": name,
        "version": "0.2",
        "description": description,
        "cases": deepcopy(cases),
    }


def _build_matrix_cases() -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    covered_entities = [
        "API_KEY",
        "OTHER_SECRET",
        "US_SSN",
        "MRN",
        "MEDICATION",
        "CREDIT_CARD",
        "IBAN",
        "EMAIL",
        "PHONE",
    ]
    for entity in covered_entities:
        for surface in SURFACES:
            value = _sample(entity, len(cases))
            cases.append(_covered_case("matrix", entity, surface, value, len(cases)))
    known_gap_surfaces = [
        "output.content",
        "output.reasoning",
        "output.tool_calls.arguments",
        "logs.traces",
    ]
    for slug, category, values, text in KNOWN_GAPS:
        for surface in known_gap_surfaces:
            cases.append(_known_gap_case("matrix", slug, category, surface, values, text))
    return cases


def _build_utility_cases() -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    benign_groups = {
        "utility-developer-prose": [
            "The vLLM service runs on port 8000 inside the local model network with one model loaded.",
            "The eval runner compares blocked counts and JSON validity after each pass.",
            "Use the local gateway only after the upstream health endpoint responds.",
            "The scanner should preserve ordinary architecture notes and benchmark prose.",
            "A developer can keep this note in a README without losing useful context.",
            "The retry loop backs off after transient provider errors and records status codes.",
        ],
        "utility-code-placeholders": [
            "const token = process.env.API_TOKEN; const url = process.env.API_URL;",
            "api_key = os.environ['OPENAI_API_KEY']; base_url = os.environ['BASE_URL']",
            "password = PASSWORD_PLACEHOLDER  # never commit a real value here",
            "headers = {'Authorization': f'Bearer {TOKEN_PLACEHOLDER}'}",
            "Set LSDF_UPSTREAM_BASE_URL in the local env file for gateway tests.",
            "settings name uses a dev only sample value",
        ],
        "utility-stack-traces": [
            "Traceback File app/main.py line 42 in run_handler raised ValueError invalid state",
            "ERROR worker retry count three for eval matrix job while retrying",
            "at Object.render (/src/components/App.tsx:88:12) while testing layout",
            "panic at src/main.rs:17 called Result unwrap on Err during dry run",
            "pytest tests/test_gateway.py::test_forwarding PASSED in 0.12s",
            "HTTP 502 from upstream during local smoke test with no body returned",
        ],
        "utility-model-config": [
            "The demo model profile serves a placeholder model with max context length 32768",
            "LM Studio listens on localhost port 1234 with an OpenAI compatible endpoint.",
            "Local model serving can use a native app or a container app.",
            "The benchmark label is demo local and the score is informational.",
            "Use FP8 KV cache only when the serving profile documents the tradeoff.",
            "The Docker network is named local model network for local development.",
        ],
        "utility-public-figures": [
            "Compare public comments by Sam Altman, Satya Nadella, and Jensen Huang.",
            "Summarize published interviews with Fei-Fei Li and Andrew Ng about education.",
            "List public statements from Lina Khan about technology competition.",
            "Discuss Grace Hopper's historical role in compiler development.",
            "Contrast Ada Lovelace and Alan Turing in a classroom lesson.",
            "Write a neutral biography paragraph about Margaret Hamilton's NASA work.",
        ],
        "utility-urls-paths": [
            "Fetch https://example.org/v1/users and //api.example.com/v1/status for docs.",
            "Read config/settings.yml before running app/main.py in the sample project.",
            "The package path is src/lsdf/eval_matrix.py and the docs path is docs/measured-protection.md.",
            "Open http://localhost:8000/health during the local vLLM smoke check.",
            "The relative route /v1/chat/completions is proxied by the gateway.",
            "Static assets live under public/images/demo.png in the example app.",
        ],
        "utility-json-schema": [
            '{"type":"object","properties":{"token":{"type":"string"}}}',
            '{"tool":"search","arguments":{"query":"public docs","limit":5}}',
            '{"status":"ok","metrics":{"latency_ms":42,"blocked":0}}',
            '{"env":{"UPSTREAM_BASE_URL":"http://localhost:8000/v1"}}',
            '{"rules":[{"entity":"EMAIL","action":"redact"}]}',
            '{"example":{"authorization_header":"Bearer PLACEHOLDER"}}',
        ],
        "utility-sql": [
            "SELECT id, email_opt_in FROM users WHERE created_at > CURRENT_DATE;",
            "UPDATE jobs SET status = 'done' WHERE id = 42;",
            "CREATE INDEX idx_messages_role ON messages(role);",
            "EXPLAIN ANALYZE SELECT count(*) FROM eval_cases;",
            "INSERT INTO audit_counts(bucket, total) VALUES ('safe', 7);",
            "DELETE FROM temp_rows WHERE expires_at < now();",
        ],
        "utility-docs-snippets": [
            "Run docker compose run --rm cli eval evals/basic.json.",
            "Profiles are full policies until domain-pack composition lands later.",
            "Known gaps are measured misses, not accidental green test cases.",
            "The README should teach local users how to plug in the gateway quickly.",
            "Detector adapters stay optional until the proof matrix shows their value.",
            "Markdown reports are for humans and JSON reports are for automation.",
        ],
        "utility-business-benign": [
            "Acme is a fictional vendor in this sample proposal and no account is present.",
            "The renewal deck uses placeholder pricing bands for a mock customer.",
            "Quarterly planning notes mention hiring themes without employee records.",
            "The incident review describes a simulated outage in the staging system.",
            "Contract language in this fixture is public boilerplate for demos.",
            "A support queue summary can mention volume trends without private tickets.",
        ],
    }
    for category, texts in benign_groups.items():
        for text in texts:
            surface = SURFACES[len(cases) % len(SURFACES)]
            cases.append(_utility_case(category, surface, text, len(cases)))
    false_positive_gaps = [
        ("benign-icd-ticket", "Release J45.909 is the internal milestone tag, not diagnosis data"),
        ("benign-icd-module", "Module E11A handles import queues in a synthetic code sample"),
        ("benign-icd-sku", "SKU A12.34 moved from warehouse bin seven to bin nine"),
        ("benign-lab-label", "Dashboard label HDL 80 belongs to a chart mock, not a lab result"),
        ("benign-medication-doc", "The detector docs include metformin 500mg as a synthetic example"),
    ]
    for slug, text in false_positive_gaps:
        cases.append(_utility_case("known-gap-benign-medical-fp", "input.messages", text, len(cases), known_gap=True, slug=slug))
    return cases


def _build_observability_cases() -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    observed_surfaces = ["logs.traces", "output.reasoning", "output.tool_calls.arguments"]
    for entity in ["API_KEY", "OTHER_SECRET", "US_SSN", "MRN", "MEDICATION", "CREDIT_CARD", "IBAN"]:
        for surface in observed_surfaces:
            value = _sample(entity, len(cases))
            cases.append(_covered_case("observability", entity, surface, value, len(cases)))
    transcript_entities = ["API_KEY", "OTHER_SECRET", "US_SSN", "MRN", "MEDICATION", "CREDIT_CARD", "IBAN"]
    for entity in transcript_entities:
        value = _sample(entity, len(cases))
        text = _text_for_entity(entity, value, len(cases))
        case = _covered_case("observability-transcript", entity, "logs.traces", value, len(cases))
        case["id"] = f"observability-transcript-{_slug(entity)}-{len(cases):03d}"
        case["payload"] = {"transcript": [{"role": "assistant", "content": text}]}
        cases.append(case)
    trace_keys = ["trace", "logs", "spans", "transcript"]
    for idx, key in enumerate(trace_keys):
        value = _sample("MRN", idx)
        case = _covered_case("observability-trace-key", "MRN", "logs.traces", value, len(cases))
        case["id"] = f"observability-{key}-mrn-redacted-{idx:03d}"
        case["payload"] = {key: [{"message": _text_for_entity("MRN", value, idx)}]}
        cases.append(case)
    benign_logs = [
        "trace span completed in 42ms for route /v1/chat/completions",
        "observability sink received two chunks and zero policy decisions",
        "tool executor invoked get_weather with city Boston and units metric",
        "reasoning summary says choose the shorter branch because it is cheaper",
        "transcript line contains a public release note and no private data",
        "logger wrote request_id req-local-demo and status success",
        "span attributes include model demo-model and profile default",
        "debug payload has cache_hit true and retry_count zero",
    ]
    for text in benign_logs:
        surface = ["logs.traces", "output.reasoning", "output.tool_calls.arguments"][len(cases) % 3]
        cases.append(_utility_case("observability-benign", surface, text, len(cases)))
    return cases


def _covered_case(prefix: str, entity: str, surface: str, value: str, idx: int) -> dict[str, Any]:
    text = _text_for_entity(entity, value, idx)
    action = _expected_action(entity, surface)
    detector_id, detector_family = DETECTOR_EXPECTATIONS[entity]
    case = {
        "id": f"{prefix}-{_slug(entity)}-{_slug(surface)}-{idx:03d}",
        "category": _category_for_entity(entity),
        "surface": surface,
        "payload": _payload_for_surface(surface, text),
        "sensitive_values": [value],
        "expected_blocked": action == "block",
        "expected_entities": [entity],
        "expected_surfaces": [surface],
        "expected_actions": [action],
        "expected_detector_ids": [detector_id],
        "expected_detector_families": [detector_family],
    }
    if entity in LOW_NOISE_ENTITIES:
        case["expected_unchanged"] = True
    elif action in {"block", "redact", "tokenize"}:
        case["expected_absent"] = [value]
    else:
        case["expected_unchanged"] = True
    if surface == "output.tool_calls.arguments":
        case["expected_valid_json_pointers"] = [_tool_arguments_pointer()]
    return case


def _known_gap_case(
    prefix: str,
    slug: str,
    category: str,
    surface: str,
    values: list[str],
    text: str,
) -> dict[str, Any]:
    case = {
        "id": f"{prefix}-{slug}-{_slug(surface)}",
        "category": category,
        "surface": surface,
        "known_gap": True,
        "payload": _payload_for_surface(surface, text),
        "sensitive_values": values,
        "expected_absent": values,
        "expected_blocked": False,
        "expected_unchanged": True,
    }
    if surface == "output.tool_calls.arguments":
        case["expected_valid_json_pointers"] = [_tool_arguments_pointer()]
    return case


def _utility_case(
    category: str,
    surface: str,
    text: str,
    idx: int,
    *,
    known_gap: bool = False,
    slug: str | None = None,
) -> dict[str, Any]:
    case = {
        "id": f"utility-{slug or _slug(category)}-{_slug(surface)}-{idx:03d}",
        "category": category,
        "surface": surface,
        "payload": _payload_for_surface(surface, text),
        "expected_blocked": False,
        "expected_no_findings": True,
        "expected_no_decisions": True,
        "expected_unchanged": True,
    }
    if known_gap:
        case["known_gap"] = True
    if surface == "output.tool_calls.arguments":
        case["expected_valid_json_pointers"] = [_tool_arguments_pointer()]
    return case


def _expected_action(entity: str, surface: str) -> str:
    if entity in LOW_NOISE_ENTITIES:
        return "redact"
    if entity in SECRET_ENTITIES:
        if surface == "output.content":
            return "redact"
        return "block"
    if entity in HARD_IDENTIFIER_ENTITIES:
        if surface in INPUT_SURFACES:
            return "tokenize"
        if surface == "output.tool_calls.arguments":
            return "block"
        return "redact"
    raise ValueError(f"No expected action for entity: {entity}")


def _category_for_entity(entity: str) -> str:
    if entity in SECRET_ENTITIES:
        return "credentials"
    if entity in {"US_SSN", "EMAIL", "PHONE"}:
        return "pii"
    if entity in {"MRN", "MEDICATION"}:
        return "phi"
    if entity in {"CREDIT_CARD", "IBAN"}:
        return "financial"
    return "uncategorized"


def _payload_for_surface(surface: str, text: str) -> dict[str, Any]:
    if surface == "input.messages":
        return {"messages": [{"role": "user", "content": text}]}
    if surface == "input.rag_context":
        return {
            "messages": [{"role": "user", "content": "Summarize the retrieved context."}],
            "rag_context": [text],
        }
    if surface == "input.tool_results":
        return {"messages": [{"role": "tool", "content": text}]}
    if surface == "output.content":
        return {"choices": [{"message": {"content": text}}]}
    if surface == "output.reasoning":
        return {"choices": [{"message": {"reasoning_content": text}}]}
    if surface == "output.tool_calls.arguments":
        return {
            "choices": [
                {
                    "message": {
                        "tool_calls": [
                            {
                                "function": {
                                    "name": "eval_tool",
                                    "arguments": json.dumps({"note": text, "ok": "yes"}),
                                }
                            }
                        ]
                    }
                }
            ]
        }
    if surface == "logs.traces":
        return {"trace": {"span": text}}
    raise ValueError(f"Unknown surface: {surface}")


def _tool_arguments_pointer() -> list[str | int]:
    return ["choices", 0, "message", "tool_calls", 0, "function", "arguments"]


def _text_for_entity(entity: str, value: str, idx: int) -> str:
    labels = {
        "API_KEY": "API key",
        "OTHER_SECRET": "credential specimen",
        "US_SSN": "SSN",
        "MRN": "medical record number",
        "MEDICATION": "clinical detail",
        "CREDIT_CARD": "payment card",
        "IBAN": "IBAN",
        "EMAIL": "contact email",
        "PHONE": "callback number",
    }
    return f"Eval case {idx} contains {labels[entity]} {value} for policy verification"


def _sample(entity: str, idx: int) -> str:
    values = ENTITY_SAMPLES[entity]
    return values[idx % len(values)]


def _slug(value: str) -> str:
    return value.lower().replace(".", "-").replace("_", "-").replace(" ", "-")


def _write_dataset(path: Path, dataset: dict[str, Any]) -> None:
    path.write_text(json.dumps(dataset, indent=2) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m lsdf.eval_matrix")
    parser.add_argument(
        "--battery",
        choices=("matrix", "utility", "observability", "all"),
        default="matrix",
    )
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument("--output-dir", type=Path, default=None)
    args = parser.parse_args(argv)

    if args.output and args.output_dir:
        parser.error("--output and --output-dir cannot be used together")
    if args.output and args.battery == "all":
        parser.error("--battery all requires --output-dir or stdout")

    datasets = build_eval_batteries(args.battery)
    if args.output is not None:
        dataset = next(iter(datasets.values()))
        _write_dataset(args.output, dataset)
        return 0
    if args.output_dir is not None:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        for battery, dataset in datasets.items():
            _write_dataset(args.output_dir / BATTERY_FILENAMES[battery], dataset)
        return 0
    if args.battery == "all":
        print(json.dumps(datasets, indent=2))
        return 0
    print(json.dumps(next(iter(datasets.values())), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
