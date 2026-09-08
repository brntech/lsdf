# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from .artifacts import write_optional_detector_artifacts
from .audit import purge_rotated_audit_files
from .comparison import compare_detector_sets, parse_detector_set
from .detectors import DetectorUnavailableError
from .engine import Firewall
from .gateway import GatewayConfigError, resolve_gateway_config, serve_gateway
from .observability import sanitize_observability
from .policy import (
    load_effective_policy,
    load_policy,
    load_policy_profile,
    policy_validation_notes,
)
from .reporting import format_detector_comparison_markdown, format_eval_report_markdown
from .security_ops import (
    diff_policy_files,
    explain_loaded_policy,
    format_policy_diff_markdown,
    format_adapter_list_markdown,
    format_adapter_list_text,
    format_entity_list_markdown,
    format_entity_list_text,
    explain_policy_file,
    format_policy_explain_markdown,
    format_policy_explain_text,
    generate_policy_keypair,
    list_adapter_families,
    list_entity_vocabulary,
    sign_policy_file,
    validate_policy_file,
    verify_policy_signature,
)
from .ux import (
    audit_export,
    audit_summary,
    benchmark_payload,
    demo_script,
    demo_report,
    doctor_report,
    explain_payload,
    format_audit_summary_text,
    format_benchmark_markdown,
    format_demo_text,
    format_doctor_text,
    format_explain_text,
    format_metrics_summary,
    format_protection_report_markdown,
    format_proof_bundle_markdown,
    format_quickstart_report_markdown,
    format_quickstart_report_text,
    format_security_report_markdown,
    format_simulate_policy_markdown,
    format_smoke_text,
    init_env_file,
    metrics_summary,
    proof_bundle,
    protection_report,
    quickstart_report,
    security_report,
    simulate_policy,
    smoke_report,
)
from .vault import (
    EncryptedSqliteTokenVault,
    backup_vault,
    check_vault,
    generate_vault_key,
    rotate_vault_key,
    vault_status,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="lsdf")
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate_parser = subparsers.add_parser("policy-validate")
    validate_parser.add_argument("policy", type=Path, nargs="?")
    validate_parser.add_argument("--profile", default=None)
    validate_parser.add_argument("--domain-pack", dest="domain_packs", action="append", default=None)

    scan_parser = subparsers.add_parser("scan")
    scan_parser.add_argument("payload", type=Path)
    scan_parser.add_argument("--policy", type=Path, default=None)
    scan_parser.add_argument("--profile", default=None)
    scan_parser.add_argument("--domain-pack", dest="domain_packs", action="append", default=None)

    observability_parser = subparsers.add_parser("sanitize-observability")
    observability_parser.add_argument("payload", type=Path)
    observability_parser.add_argument("--policy", type=Path, default=None)
    observability_parser.add_argument("--profile", default=None)
    observability_parser.add_argument("--domain-pack", dest="domain_packs", action="append", default=None)
    observability_parser.add_argument("--format", choices=("json",), default="json")

    eval_parser = subparsers.add_parser("eval")
    eval_parser.add_argument("dataset", type=Path)
    eval_parser.add_argument("--policy", type=Path, default=None)
    eval_parser.add_argument("--profile", default=None)
    eval_parser.add_argument("--domain-pack", dest="domain_packs", action="append", default=None)
    eval_parser.add_argument("--format", choices=("json", "markdown"), default="json")
    eval_parser.add_argument("--reveal-sensitive-values", action="store_true")

    compare_parser = subparsers.add_parser("compare-detectors")
    compare_parser.add_argument("dataset", type=Path)
    compare_parser.add_argument("--policy", type=Path, default=None)
    compare_parser.add_argument("--profile", default=None)
    compare_parser.add_argument("--domain-pack", dest="domain_packs", action="append", default=None)
    compare_parser.add_argument("--format", choices=("json", "markdown"), default="json")
    compare_parser.add_argument("--reveal-sensitive-values", action="store_true")
    compare_parser.add_argument(
        "--set",
        dest="detector_sets",
        action="append",
        default=None,
        help="Detector set in NAME=family,family syntax. Can be passed more than once.",
    )

    artifacts_parser = subparsers.add_parser("optional-detector-artifacts")
    artifacts_parser.add_argument("--policy", type=Path, default=None)
    artifacts_parser.add_argument("--profile", default=None)
    artifacts_parser.add_argument("--domain-pack", dest="domain_packs", action="append", default=None)
    artifacts_parser.add_argument("--output-dir", type=Path, default=None)
    artifacts_parser.add_argument(
        "--dataset",
        dest="datasets",
        type=Path,
        action="append",
        default=None,
        help="Dataset path to include. Defaults to the bundled evaluation batteries.",
    )

    gateway_parser = subparsers.add_parser("gateway")
    gateway_parser.add_argument("--host", default="127.0.0.1")
    gateway_parser.add_argument("--port", type=int, default=8080)
    gateway_parser.add_argument("--policy", type=Path, default=None)
    gateway_parser.add_argument("--profile", default=None)
    gateway_parser.add_argument("--domain-pack", dest="domain_packs", action="append", default=None)
    gateway_parser.add_argument("--upstream-base-url", default=None)
    gateway_parser.add_argument("--upstream-api-key", default=None)

    doctor_parser = subparsers.add_parser("doctor")
    doctor_parser.add_argument("--policy", type=Path, default=None)
    doctor_parser.add_argument("--profile", default=None)
    doctor_parser.add_argument("--domain-pack", dest="domain_packs", action="append", default=None)
    doctor_parser.add_argument("--upstream-base-url", default=None)
    doctor_parser.add_argument("--audit-jsonl-path", type=Path, default=None)
    doctor_parser.add_argument("--metrics-jsonl-path", type=Path, default=None)
    doctor_parser.add_argument("--vault-path", type=Path, default=None)
    doctor_parser.add_argument("--format", choices=("text", "json"), default="text")

    init_parser = subparsers.add_parser("init")
    init_parser.add_argument(
        "--upstream",
        choices=("demo", "vllm", "lmstudio", "ollama", "litellm", "openrouter", "custom"),
        required=True,
    )
    init_parser.add_argument("--upstream-base-url", default=None)
    init_parser.add_argument("--profile", default="default")
    init_parser.add_argument("--domain-pack", dest="domain_packs", action="append", default=None)
    init_parser.add_argument("--audit-jsonl-path", default=None)
    init_parser.add_argument("--metrics-jsonl-path", default=None)
    init_parser.add_argument("--vault-path", default=None)
    init_parser.add_argument("--tokenization-mode", choices=("irreversible", "vault"), default="irreversible")
    init_parser.add_argument("--output", type=Path, default=Path(".lsdf.env"))
    init_parser.add_argument("--force", action="store_true")

    demo_parser = subparsers.add_parser("demo")
    demo_parser.add_argument("--profile", default="default")
    demo_parser.add_argument("--domain-pack", dest="domain_packs", action="append", default=None)
    demo_parser.add_argument("--format", choices=("text", "json"), default="text")

    demo_script_parser = subparsers.add_parser("demo-script")
    demo_script_parser.add_argument("--format", choices=("text", "markdown"), default="text")

    explain_parser = subparsers.add_parser("explain")
    explain_parser.add_argument("payload", type=Path)
    explain_parser.add_argument("--policy", type=Path, default=None)
    explain_parser.add_argument("--profile", default=None)
    explain_parser.add_argument("--domain-pack", dest="domain_packs", action="append", default=None)
    explain_parser.add_argument(
        "--unknown-surface",
        choices=("input.messages", "output.content", "logs.traces"),
        default="input.messages",
    )
    explain_parser.add_argument("--format", choices=("text", "json"), default="text")
    explain_parser.add_argument("--include-transformed-payload", action="store_true")

    audit_summary_parser = subparsers.add_parser("audit-summary")
    audit_summary_parser.add_argument("audit_jsonl", type=Path)
    audit_summary_parser.add_argument("--format", choices=("text", "json"), default="text")

    benchmark_parser = subparsers.add_parser("benchmark")
    benchmark_parser.add_argument("payload", type=Path)
    benchmark_parser.add_argument("--policy", type=Path, default=None)
    benchmark_parser.add_argument("--profile", default=None)
    benchmark_parser.add_argument("--domain-pack", dest="domain_packs", action="append", default=None)
    benchmark_parser.add_argument("--mode", choices=("scan", "observability"), default="scan")
    benchmark_parser.add_argument("--iterations", type=int, default=50)
    benchmark_parser.add_argument("--format", choices=("json", "markdown"), default="json")

    protection_parser = subparsers.add_parser("protection-report")
    protection_parser.add_argument("--policy", type=Path, default=None)
    protection_parser.add_argument("--profile", default=None)
    protection_parser.add_argument("--domain-pack", dest="domain_packs", action="append", default=None)
    protection_parser.add_argument("--dataset", dest="datasets", type=Path, action="append", default=None)
    protection_parser.add_argument("--format", choices=("markdown", "json"), default="markdown")

    fp_lever_parser = subparsers.add_parser("fp-lever-table")
    fp_lever_parser.add_argument(
        "--threshold", dest="thresholds", type=float, action="append", default=None,
        help="OpenAI privacy-filter score threshold to evaluate. Repeatable. "
             "Defaults to 0.50, 0.70, 0.85, 0.95.",
    )
    fp_lever_parser.add_argument(
        "--threat-dataset", type=Path, default=None,
        help="Threat dataset (defaults to evals/piece_b_replay.json).",
    )
    fp_lever_parser.add_argument(
        "--benign-dataset", dest="benign_datasets", type=Path, action="append", default=None,
        help="Benign dataset path. Repeatable.",
    )
    fp_lever_parser.add_argument("--profile", default=None)
    fp_lever_parser.add_argument(
        "--format", choices=("markdown", "json"), default="markdown",
    )

    latency_table_parser = subparsers.add_parser("latency-table")
    latency_table_parser.add_argument(
        "--profile", dest="profiles", action="append", default=None,
        help="Profile to benchmark. Repeatable. Defaults to default + balanced + broad-pii + broad-pii-ml.",
    )
    latency_table_parser.add_argument("--iterations", type=int, default=50)
    latency_table_parser.add_argument(
        "--format", choices=("markdown", "json"), default="markdown",
    )

    eval_report_parser = subparsers.add_parser("eval-report")
    eval_report_parser.add_argument(
        "--profile", dest="profiles", action="append", default=None,
        help="Policy profile to include. Repeatable. Defaults to default + balanced + broad-pii + broad-pii-ml.",
    )
    eval_report_parser.add_argument(
        "--threat-dataset", dest="threat_datasets", type=Path, action="append", default=None,
        help=(
            "Threat dataset path. Repeatable; supplying paths replaces the default set. "
            "Defaults to piece_b_replay + medical_phi_replay + nemotron_pii + "
            "br_agentic_pii. External benchmarks must be supplied explicitly."
        ),
    )
    eval_report_parser.add_argument(
        "--benign-dataset", dest="benign_datasets", type=Path, action="append", default=None,
        help="Benign dataset path. Repeatable. Defaults to false_positive + utility_matrix.",
    )
    eval_report_parser.add_argument(
        "--benchmark-payload", type=Path, default=None,
        help="Payload to time per profile (defaults to examples/openai_request.json).",
    )
    eval_report_parser.add_argument("--iterations", type=int, default=50)
    eval_report_parser.add_argument("--format", choices=("markdown", "json"), default="markdown")

    detectors_parser = subparsers.add_parser("detectors")
    detectors_sub = detectors_parser.add_subparsers(dest="detectors_command", required=True)
    detectors_recall = detectors_sub.add_parser("recall")
    detectors_recall.add_argument("--all", action="store_true")
    detectors_recall.add_argument("--gaps", action="store_true")
    detectors_recall.add_argument("--regenerate", action="store_true")
    detectors_recall.add_argument("--format", choices=("markdown", "json"), default="markdown")
    detectors_recall.add_argument("--output", type=Path, default=None)
    detectors_recall.add_argument("--history", type=Path, default=None)

    miss_parser = subparsers.add_parser("miss-analysis")
    miss_parser.add_argument("dataset", type=Path)
    miss_parser.add_argument("--policy", type=Path, default=None)
    miss_parser.add_argument("--profile", default=None)
    miss_parser.add_argument("--domain-pack", dest="domain_packs", action="append", default=None)
    miss_parser.add_argument("--format", choices=("json",), default="json")

    metrics_summary_parser = subparsers.add_parser("metrics-summary")
    metrics_summary_parser.add_argument("metrics_jsonl", type=Path)
    metrics_summary_parser.add_argument("--format", choices=("text", "json", "markdown"), default="text")

    smoke_parser = subparsers.add_parser("smoke")
    smoke_parser.add_argument("--gateway-base-url", default=None)
    smoke_parser.add_argument("--upstream-base-url", default=None)
    smoke_parser.add_argument("--audit-jsonl-path", type=Path, default=None)
    smoke_parser.add_argument("--format", choices=("text", "json"), default="text")

    quickstart_parser = subparsers.add_parser("quickstart-report")
    quickstart_parser.add_argument("--gateway-base-url", required=True)
    quickstart_parser.add_argument("--audit-jsonl-path", type=Path, default=None)
    quickstart_parser.add_argument("--metrics-jsonl-path", type=Path, default=None)
    quickstart_parser.add_argument("--format", choices=("text", "json", "markdown"), default="text")

    vault_parser = subparsers.add_parser("vault")
    vault_sub = vault_parser.add_subparsers(dest="vault_command", required=True)
    vault_sub.add_parser("keygen")
    vault_status = vault_sub.add_parser("status")
    vault_status.add_argument("--vault-path", type=Path, required=True)
    vault_check = vault_sub.add_parser("check")
    vault_check.add_argument("--vault-path", type=Path, required=True)
    vault_backup = vault_sub.add_parser("backup")
    vault_backup.add_argument("--vault-path", type=Path, required=True)
    vault_backup.add_argument("--output", type=Path, required=True)
    vault_rotate = vault_sub.add_parser("rotate-key")
    vault_rotate.add_argument("--vault-path", type=Path, required=True)
    vault_rotate.add_argument("--old-key-env", default="LSDF_OLD_VAULT_KEY")
    vault_rotate.add_argument("--new-key-env", default="LSDF_NEW_VAULT_KEY")
    vault_rotate.add_argument("--output", type=Path, required=True)
    vault_resolve = vault_sub.add_parser("resolve")
    vault_resolve.add_argument("token")
    vault_resolve.add_argument("--vault-path", type=Path, required=True)
    vault_resolve.add_argument("--vault-key-env", default="LSDF_VAULT_KEY")
    vault_resolve.add_argument("--reveal-sensitive-value", action="store_true")

    simulate_parser = subparsers.add_parser("simulate-policy")
    simulate_parser.add_argument("fixtures", type=Path, nargs="+")
    simulate_parser.add_argument("--policy", type=Path, default=None)
    simulate_parser.add_argument("--profile", default=None)
    simulate_parser.add_argument("--domain-pack", dest="domain_packs", action="append", default=None)
    simulate_parser.add_argument("--format", choices=("json", "markdown"), default="json")

    audit_export_parser = subparsers.add_parser("audit-export")
    audit_export_parser.add_argument("audit_jsonl", type=Path)
    audit_export_parser.add_argument("--target", choices=("generic", "splunk", "elastic", "datadog"), default="generic")
    audit_export_parser.add_argument("--format", choices=("jsonl",), default="jsonl")

    audit_purge_parser = subparsers.add_parser(
        "audit-purge",
        help=(
            "Delete rotated audit backups older than --older-than-days. The live "
            "audit file is never touched."
        ),
    )
    audit_purge_parser.add_argument("audit_jsonl", type=Path)
    audit_purge_parser.add_argument("--older-than-days", type=int, required=True)
    audit_purge_parser.add_argument("--format", choices=("json",), default="json")
    audit_purge_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Report which files would be deleted without removing them.",
    )

    adapters_parser = subparsers.add_parser("adapters")
    adapters_sub = adapters_parser.add_subparsers(dest="adapters_command", required=True)
    adapters_list = adapters_sub.add_parser("list")
    adapters_list.add_argument("--format", choices=("text", "json", "markdown"), default="text")

    entities_parser = subparsers.add_parser("entities")
    entities_sub = entities_parser.add_subparsers(dest="entities_command", required=True)
    entities_list = entities_sub.add_parser("list")
    entities_list.add_argument("--format", choices=("text", "json", "markdown"), default="text")

    policy_parser = subparsers.add_parser("policy")
    policy_sub = policy_parser.add_subparsers(dest="policy_command", required=True)
    policy_keygen = policy_sub.add_parser("keygen")
    policy_keygen.add_argument("--public-key", type=Path, required=True)
    policy_keygen.add_argument("--private-key", type=Path, required=True)
    policy_validate = policy_sub.add_parser("validate")
    policy_validate.add_argument("policy", type=Path)
    policy_diff = policy_sub.add_parser("diff")
    policy_diff.add_argument("old_policy", type=Path)
    policy_diff.add_argument("new_policy", type=Path)
    policy_diff.add_argument("--format", choices=("json", "markdown"), default="markdown")
    policy_explain = policy_sub.add_parser("explain")
    policy_explain.add_argument("policy", type=Path, nargs="?")
    policy_explain.add_argument("--profile", default=None)
    policy_explain.add_argument("--domain-pack", dest="domain_packs", action="append", default=None)
    policy_explain.add_argument("--format", choices=("text", "json", "markdown"), default="text")
    policy_sign = policy_sub.add_parser("sign")
    policy_sign.add_argument("policy", type=Path)
    policy_sign.add_argument("--private-key", type=Path, default=None)
    policy_sign.add_argument("--output", type=Path, required=True)
    policy_verify = policy_sub.add_parser("verify")
    policy_verify.add_argument("policy", type=Path)
    policy_verify.add_argument("--signature", type=Path, default=None)
    policy_verify.add_argument("--public-key", type=Path, default=None)

    security_parser = subparsers.add_parser("security-report")
    security_parser.add_argument("--policy", type=Path, default=None)
    security_parser.add_argument("--profile", default=None)
    security_parser.add_argument("--domain-pack", dest="domain_packs", action="append", default=None)
    security_parser.add_argument("--audit-jsonl-path", type=Path, default=None)
    security_parser.add_argument("--format", choices=("json", "markdown"), default="markdown")

    proof_parser = subparsers.add_parser("proof-bundle")
    proof_parser.add_argument("--output", type=Path, required=True)
    proof_parser.add_argument("--policy", type=Path, default=None)
    proof_parser.add_argument("--profile", default=None)
    proof_parser.add_argument("--domain-pack", dest="domain_packs", action="append", default=None)
    proof_parser.add_argument("--audit-jsonl-path", type=Path, default=None)
    proof_parser.add_argument("--metrics-jsonl-path", type=Path, default=None)
    proof_parser.add_argument("--format", choices=("markdown", "json"), default="markdown")

    args = parser.parse_args(argv)

    if args.command == "policy-validate":
        try:
            policy = _load_policy(args.policy, args.profile, getattr(args, "domain_packs", None))
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        summary = policy.summary()
        notes = policy_validation_notes(
            policy,
            profile=args.profile,
            domain_packs=getattr(args, "domain_packs", None),
        )
        if notes:
            summary["notes"] = notes
        print(json.dumps(summary, indent=2))
        return 0

    if args.command == "scan":
        firewall = Firewall(_load_policy(args.policy, args.profile, args.domain_packs))
        payload = _read_json(args.payload)
        result = firewall.inspect(payload)
        print(json.dumps(result.to_dict(), indent=2))
        return 1 if result.blocked else 0

    if args.command == "sanitize-observability":
        firewall = Firewall(_load_policy(args.policy, args.profile, args.domain_packs))
        payload = _read_json(args.payload)
        result = sanitize_observability(payload, firewall)
        print(json.dumps(result.to_dict(), indent=2))
        return 1 if result.blocked else 0

    if args.command == "eval":
        policy = _load_policy(args.policy, args.profile, args.domain_packs)
        firewall = Firewall(policy)
        dataset = _read_json(args.dataset)
        report = firewall.evaluate(
            dataset["cases"],
            reveal_sensitive_values=args.reveal_sensitive_values,
        )
        report = _annotate_eval_report(report, dataset, args.dataset, policy, firewall)
        if args.format == "markdown":
            print(format_eval_report_markdown(report), end="")
        else:
            print(json.dumps(report, indent=2))
        return 1 if report["failed"] else 0

    if args.command == "compare-detectors":
        try:
            detector_sets = (
                [parse_detector_set(value) for value in args.detector_sets]
                if args.detector_sets
                else None
            )
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        policy = _load_policy(args.policy, args.profile, args.domain_packs)
        dataset = _read_json(args.dataset)
        report = compare_detector_sets(
            policy=policy,
            dataset=dataset,
            dataset_path=args.dataset,
            detector_sets=detector_sets,
            reveal_sensitive_values=args.reveal_sensitive_values,
        )
        if args.format == "markdown":
            print(format_detector_comparison_markdown(report), end="")
        else:
            print(json.dumps(report, indent=2))
        return 0

    if args.command == "optional-detector-artifacts":
        policy = _load_policy(args.policy, args.profile, args.domain_packs)
        result = write_optional_detector_artifacts(
            policy=policy,
            output_dir=args.output_dir,
            dataset_paths=args.datasets,
        )
        print(json.dumps(result.manifest, indent=2))
        return 0

    if args.command == "gateway":
        try:
            config = resolve_gateway_config(
                policy_path=str(args.policy) if args.policy else None,
                policy_profile=args.profile,
                upstream_base_url=args.upstream_base_url,
                upstream_api_key=args.upstream_api_key,
                domain_packs=args.domain_packs,
            )
        except GatewayConfigError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        try:
            serve_gateway(
                host=args.host,
                port=args.port,
                config=config,
            )
        except DetectorUnavailableError as exc:
            print(f"Detector unavailable: {exc}", file=sys.stderr)
            return 2
        except GatewayConfigError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        return 0

    if args.command == "doctor":
        report = doctor_report(
            policy_path=args.policy,
            profile=args.profile,
            domain_packs=args.domain_packs,
            upstream_base_url=args.upstream_base_url,
            audit_jsonl_path=args.audit_jsonl_path,
            metrics_jsonl_path=args.metrics_jsonl_path,
            vault_path=args.vault_path,
        )
        if args.format == "json":
            print(json.dumps(report, indent=2))
        else:
            print(format_doctor_text(report), end="")
        return 1 if report["status"] == "error" else 0

    if args.command == "init":
        try:
            report = init_env_file(
                upstream=args.upstream,
                upstream_base_url=args.upstream_base_url,
                profile=args.profile,
                domain_packs=args.domain_packs,
                audit_jsonl_path=args.audit_jsonl_path,
                metrics_jsonl_path=args.metrics_jsonl_path,
                vault_path=args.vault_path,
                tokenization_mode=args.tokenization_mode,
                output=args.output,
                force=args.force,
            )
        except (ValueError, FileExistsError) as exc:
            print(str(exc), file=sys.stderr)
            return 2
        print(json.dumps(report, indent=2))
        return 0

    if args.command == "demo":
        try:
            report = demo_report(profile=args.profile, domain_packs=args.domain_packs)
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        if args.format == "json":
            print(json.dumps(report, indent=2))
        else:
            print(format_demo_text(report), end="")
        return 0

    if args.command == "demo-script":
        print(demo_script(output_format=args.format), end="")
        return 0

    if args.command == "explain":
        try:
            report = explain_payload(
                _read_json(args.payload),
                policy_path=args.policy,
                profile=args.profile,
                domain_packs=args.domain_packs,
                unknown_surface=args.unknown_surface,
                include_transformed_payload=args.include_transformed_payload,
            )
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        if args.format == "json":
            print(json.dumps(report, indent=2))
        else:
            print(format_explain_text(report), end="")
        return 1 if report["blocked"] else 0

    if args.command == "audit-summary":
        try:
            report = audit_summary(args.audit_jsonl)
        except FileNotFoundError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        if args.format == "json":
            print(json.dumps(report, indent=2))
        else:
            print(format_audit_summary_text(report), end="")
        return 1 if report["malformed_lines"] else 0

    if args.command == "benchmark":
        try:
            report = benchmark_payload(
                _read_json(args.payload),
                policy_path=args.policy,
                profile=args.profile,
                domain_packs=args.domain_packs,
                mode=args.mode,
                iterations=args.iterations,
            )
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        if args.format == "markdown":
            print(format_benchmark_markdown(report), end="")
        else:
            print(json.dumps(report, indent=2))
        return 0

    if args.command == "protection-report":
        try:
            report = protection_report(
                policy_path=args.policy,
                profile=args.profile,
                domain_packs=args.domain_packs,
                dataset_paths=args.datasets,
            )
        except (ValueError, FileNotFoundError, KeyError) as exc:
            print(str(exc), file=sys.stderr)
            return 2
        if args.format == "json":
            print(json.dumps(report, indent=2))
        else:
            print(format_protection_report_markdown(report), end="")
        return 1 if report["totals"]["failed"] else 0

    if args.command == "fp-lever-table":
        from .fp_lever_measurement import (
            DEFAULT_BENIGN_DATASETS as FP_DEFAULT_BENIGN,
            DEFAULT_PROFILE as FP_DEFAULT_PROFILE,
            DEFAULT_THREAT_DATASET as FP_DEFAULT_THREAT,
            DEFAULT_THRESHOLDS,
            format_threshold_sweep_markdown,
            run_threshold_sweep,
        )
        try:
            report = run_threshold_sweep(
                thresholds=tuple(args.thresholds) if args.thresholds else DEFAULT_THRESHOLDS,
                threat_dataset=args.threat_dataset or FP_DEFAULT_THREAT,
                benign_datasets=(
                    tuple(args.benign_datasets)
                    if args.benign_datasets
                    else FP_DEFAULT_BENIGN
                ),
                profile_name=args.profile or FP_DEFAULT_PROFILE,
            )
        except (FileNotFoundError, ValueError) as exc:
            print(str(exc), file=sys.stderr)
            return 2
        if args.format == "json":
            print(json.dumps(report, indent=2))
        else:
            print(format_threshold_sweep_markdown(report), end="")
        return 0

    if args.command == "latency-table":
        from .latency_suite import (
            DEFAULT_PROFILES as LATENCY_DEFAULT_PROFILES,
            format_latency_suite_markdown,
            run_latency_suite,
        )
        try:
            report = run_latency_suite(
                profiles=tuple(args.profiles) if args.profiles else LATENCY_DEFAULT_PROFILES,
                iterations=args.iterations,
            )
        except (ValueError, FileNotFoundError) as exc:
            print(str(exc), file=sys.stderr)
            return 2
        if args.format == "json":
            print(json.dumps(report, indent=2))
        else:
            print(format_latency_suite_markdown(report), end="")
        return 0

    if args.command == "eval-report":
        from .release_eval import (
            DEFAULT_BENCHMARK_PAYLOAD,
            DEFAULT_BENIGN_DATASETS,
            DEFAULT_PROFILES,
            DEFAULT_THREAT_DATASETS,
            format_release_evaluation_markdown,
            release_evaluation,
        )
        try:
            report = release_evaluation(
                profiles=tuple(args.profiles) if args.profiles else DEFAULT_PROFILES,
                threat_datasets=(
                    tuple(args.threat_datasets)
                    if args.threat_datasets
                    else DEFAULT_THREAT_DATASETS
                ),
                benign_datasets=(
                    tuple(args.benign_datasets)
                    if args.benign_datasets
                    else DEFAULT_BENIGN_DATASETS
                ),
                benchmark_payload=args.benchmark_payload or DEFAULT_BENCHMARK_PAYLOAD,
                iterations=args.iterations,
            )
        except (FileNotFoundError, ValueError) as exc:
            print(str(exc), file=sys.stderr)
            return 2
        if args.format == "json":
            print(json.dumps(report, indent=2))
        else:
            print(format_release_evaluation_markdown(report), end="")
        return 0 if report["release_gate"]["passed"] else 1

    if args.command == "detectors":
        from .system_recall import (
            DEFAULT_HISTORY_PATH,
            DEFAULT_OUTPUT_PATH,
            format_system_recall_markdown,
            regenerate_system_recall,
            system_recall_report,
        )

        try:
            if args.detectors_command == "recall":
                if args.regenerate:
                    report = regenerate_system_recall(
                        output_path=args.output or DEFAULT_OUTPUT_PATH,
                        history_path=args.history or DEFAULT_HISTORY_PATH,
                    )
                else:
                    report = system_recall_report()
                if args.format == "json":
                    print(json.dumps(report, indent=2))
                else:
                    print(
                        format_system_recall_markdown(
                            report["results"],
                            generated_at=report["generated_at"],
                            commit_sha=report["commit_sha"],
                            floors=report.get("floors"),
                            out_of_scope=report.get("out_of_scope"),
                            coverage_gaps=report.get("coverage_gaps"),
                            include_full_matrix=args.all or args.regenerate,
                            include_gaps=args.gaps or args.regenerate,
                        ),
                        end="",
                    )
                return 0
        except (FileNotFoundError, ValueError) as exc:
            print(str(exc), file=sys.stderr)
            return 2

    if args.command == "miss-analysis":
        policy = _load_policy(args.policy, args.profile, args.domain_packs)
        firewall = Firewall(policy)
        dataset = _read_json(args.dataset)
        report = firewall.evaluate(dataset["cases"], reveal_sensitive_values=True)
        misses = []
        for result in report["results"]:
            leaked = result.get("sensitive_values_leaked_after") or result.get("leaks_after") or []
            if leaked:
                misses.append(
                    {
                        "id": result.get("id"),
                        "surface": result.get("surface"),
                        "category": result.get("category"),
                        "finding_entities": result.get("finding_entities", []),
                        "sensitive_values_leaked_after": leaked,
                    }
                )
        print(
            json.dumps(
                {
                    "dataset": dataset.get("name", str(args.dataset)),
                    "profile": policy.name,
                    "warning": "Local debug output may reveal corpus sensitive values. Do not commit.",
                    "miss_count": len(misses),
                    "misses": misses,
                },
                indent=2,
            )
        )
        return 0

    if args.command == "metrics-summary":
        try:
            report = metrics_summary(args.metrics_jsonl)
        except FileNotFoundError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        if args.format == "json":
            print(json.dumps(report, indent=2))
        else:
            print(format_metrics_summary(report, args.format), end="")
        return 1 if report["malformed_lines"] else 0

    if args.command == "smoke":
        gateway_base_url = args.gateway_base_url or args.upstream_base_url
        if not gateway_base_url:
            print("--gateway-base-url is required", file=sys.stderr)
            return 2
        report = smoke_report(
            gateway_base_url=gateway_base_url,
            audit_jsonl_path=args.audit_jsonl_path,
            management_token=os.environ.get("LSDF_MANAGEMENT_TOKEN") or None,
        )
        if args.format == "json":
            print(json.dumps(report, indent=2))
        else:
            print(format_smoke_text(report), end="")
        return 1 if report["status"] == "error" else 0

    if args.command == "quickstart-report":
        report = quickstart_report(
            gateway_base_url=args.gateway_base_url,
            audit_jsonl_path=args.audit_jsonl_path,
            metrics_jsonl_path=args.metrics_jsonl_path,
            management_token=os.environ.get("LSDF_MANAGEMENT_TOKEN") or None,
        )
        if args.format == "json":
            print(json.dumps(report, indent=2))
        elif args.format == "markdown":
            print(format_quickstart_report_markdown(report), end="")
        else:
            print(format_quickstart_report_text(report), end="")
        return 1 if report["status"] == "error" else 0

    if args.command == "vault":
        if args.vault_command == "keygen":
            print(generate_vault_key())
            return 0
        if args.vault_command == "status":
            print(json.dumps(vault_status(args.vault_path), indent=2))
            return 0
        if args.vault_command == "check":
            report = check_vault(args.vault_path)
            print(json.dumps(report, indent=2))
            return 0 if report["valid"] else 1
        if args.vault_command == "backup":
            try:
                print(json.dumps(backup_vault(args.vault_path, args.output), indent=2))
            except ValueError as exc:
                print(str(exc), file=sys.stderr)
                return 2
            return 0
        if args.vault_command == "rotate-key":
            old_key = os.environ.get(args.old_key_env)
            new_key = os.environ.get(args.new_key_env)
            if not old_key or not new_key:
                print("Missing old or new vault key env var", file=sys.stderr)
                return 2
            try:
                report = rotate_vault_key(
                    args.vault_path,
                    args.output,
                    old_key=old_key,
                    new_key=new_key,
                )
            except ValueError as exc:
                print(str(exc), file=sys.stderr)
                return 2
            print(json.dumps(report, indent=2))
            return 0
        if args.vault_command == "resolve":
            key = os.environ.get(args.vault_key_env)
            if not key:
                print(f"Missing vault key env var: {args.vault_key_env}", file=sys.stderr)
                return 2
            vault = EncryptedSqliteTokenVault(args.vault_path, key)
            try:
                value = vault.resolve(args.token)
            except (KeyError, ValueError) as exc:
                print(str(exc), file=sys.stderr)
                return 1
            if not args.reveal_sensitive_value:
                record = vault.record(args.token)
                print(
                    json.dumps(
                        {
                            "token": record.token,
                            "entity": record.entity,
                            "created_at": record.created_at,
                            "resolved": True,
                            "value": f"[REDACTED len={len(value)}]",
                        },
                        indent=2,
                    )
                )
            else:
                print(value)
            return 0

    if args.command == "simulate-policy":
        report = simulate_policy(
            args.fixtures,
            policy_path=args.policy,
            profile=args.profile,
            domain_packs=args.domain_packs,
        )
        if args.format == "markdown":
            print(format_simulate_policy_markdown(report), end="")
        else:
            print(json.dumps(report, indent=2))
        return 1 if report["failed"] else 0

    if args.command == "audit-export":
        try:
            rows = audit_export(args.audit_jsonl, target=args.target)
        except FileNotFoundError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        for row in rows:
            print(json.dumps(row, separators=(",", ":")))
        return 0

    if args.command == "audit-purge":
        # Defensive guard against environment-variable expansion bugs that
        # produce `--older-than-days 0` and blast every rotated backup. The
        # Python function still accepts 0 for callers that genuinely want a
        # purge-everything sweep; the CLI requires >=1 because operators
        # almost always reach this path through cron, and "blank env var
        # silently purges all backups" is the wrong default surprise.
        if args.older_than_days < 1:
            print(
                "audit-purge requires --older-than-days >= 1. Call "
                "lsdf.audit.purge_rotated_audit_files programmatically if "
                "you need a 0-day sweep.",
                file=sys.stderr,
            )
            return 2
        try:
            report = purge_rotated_audit_files(
                args.audit_jsonl,
                older_than_days=args.older_than_days,
                dry_run=args.dry_run,
            )
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        print(json.dumps(report, indent=2))
        return 1 if report["errors"] else 0

    if args.command == "adapters":
        report = list_adapter_families()
        if args.format == "json":
            print(json.dumps(report, indent=2))
        elif args.format == "markdown":
            print(format_adapter_list_markdown(report), end="")
        else:
            print(format_adapter_list_text(report), end="")
        return 0

    if args.command == "entities":
        report = list_entity_vocabulary()
        if args.format == "json":
            print(json.dumps(report, indent=2))
        elif args.format == "markdown":
            print(format_entity_list_markdown(report), end="")
        else:
            print(format_entity_list_text(report), end="")
        return 0

    if args.command == "policy":
        try:
            if args.policy_command == "keygen":
                print(
                    json.dumps(
                        generate_policy_keypair(args.public_key, args.private_key),
                        indent=2,
                    )
                )
                return 0
            if args.policy_command == "validate":
                print(json.dumps(validate_policy_file(args.policy), indent=2))
                return 0
            if args.policy_command == "diff":
                report = diff_policy_files(args.old_policy, args.new_policy)
                if args.format == "json":
                    print(json.dumps(report, indent=2))
                else:
                    print(format_policy_diff_markdown(report), end="")
                return 0
            if args.policy_command == "explain":
                if args.policy is not None:
                    report = explain_policy_file(args.policy)
                else:
                    profile = args.profile or "default"
                    policy = load_effective_policy(profile, domain_packs=args.domain_packs)
                    source = f"profile:{profile}"
                    if args.domain_packs:
                        source += "+" + "+".join(f"domain-pack:{pack}" for pack in args.domain_packs)
                    report = explain_loaded_policy(policy, source=source)
                if args.format == "json":
                    print(json.dumps(report, indent=2))
                elif args.format == "markdown":
                    print(format_policy_explain_markdown(report), end="")
                else:
                    print(format_policy_explain_text(report), end="")
                return 0
            if args.policy_command == "sign":
                print(
                    json.dumps(
                        sign_policy_file(args.policy, args.output, args.private_key),
                        indent=2,
                    )
                )
                return 0
            if args.policy_command == "verify":
                report = verify_policy_signature(args.policy, args.signature, args.public_key)
                print(json.dumps(report, indent=2))
                return 0 if report["valid"] else 1
        except Exception as exc:
            print(str(exc), file=sys.stderr)
            return 2

    if args.command == "security-report":
        report = security_report(
            policy_path=args.policy,
            profile=args.profile,
            domain_packs=args.domain_packs,
            audit_jsonl_path=args.audit_jsonl_path,
        )
        if args.format == "json":
            print(json.dumps(report, indent=2))
        else:
            print(format_security_report_markdown(report), end="")
        return 0

    if args.command == "proof-bundle":
        try:
            report = proof_bundle(
                output=args.output,
                policy_path=args.policy,
                profile=args.profile,
                domain_packs=args.domain_packs,
                audit_jsonl_path=args.audit_jsonl_path,
                metrics_jsonl_path=args.metrics_jsonl_path,
                output_format=args.format,
            )
        except Exception as exc:
            print(str(exc), file=sys.stderr)
            return 2
        if args.format == "json":
            print(json.dumps(report, indent=2))
        else:
            print(format_proof_bundle_markdown(report), end="")
        return 0

    return 2


def _load_policy(
    policy_path: Path | None,
    profile: str | None,
    domain_packs: list[str] | tuple[str, ...] | None = None,
):
    if policy_path is not None:
        return load_policy(policy_path)
    if domain_packs:
        return load_effective_policy(profile or "default", domain_packs=domain_packs)
    return load_policy_profile(profile or "default")


def _annotate_eval_report(
    report: dict[str, Any],
    dataset: dict[str, Any],
    path: Path,
    policy,
    firewall,
) -> dict[str, Any]:
    detector_summary = firewall.detector_summary()
    metadata = {
        "dataset": dataset.get("name", path.name),
        "dataset_path": str(path),
        "profile": policy.name,
        "mode": policy.mode,
        "detector_families": detector_summary["detector_families"],
        "detector_ids": detector_summary["detector_ids"],
    }
    return {**metadata, **report}


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"Invalid JSON in {path}: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc


if __name__ == "__main__":
    raise SystemExit(main())
