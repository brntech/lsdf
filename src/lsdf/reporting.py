# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from typing import Any


def format_eval_report_markdown(report: dict[str, Any]) -> str:
    """Render a compact human-readable eval report from a safe report dict."""

    lines = ["# LSDF Eval Report", ""]
    lines.extend(
        [
            f"- Dataset: {report.get('dataset', 'unknown')}",
            f"- Profile: {report.get('profile', 'unknown')}",
            f"- Mode: {report.get('mode', 'unknown')}",
            f"- Detector families: {', '.join(report.get('detector_families', []))}",
            f"- Cases: {report.get('case_count', 0)}",
            f"- Passed: {report.get('passed', 0)}",
            f"- Failed: {report.get('failed', 0)}",
            f"- Evaluation errors: {report.get('evaluation_errors', 0)}",
            f"- Blocked: {report.get('blocked', 0)}",
            f"- Supported-case misses: {report.get('misses', 0)}",
            f"- Known-gap misses: {report.get('known_gap_misses', 0)}",
            f"- Mutated cases: {report.get('mutated_cases', 0)}",
            f"- Unwanted mutations: {report.get('unwanted_mutations', 0)}",
            f"- JSON text mutations: {report.get('json_text_mutations', 0)}",
            f"- Unwanted blocks: {report.get('unwanted_blocks', 0)}",
            f"- Known gaps: {report.get('known_gap_cases', 0)}",
            f"- Known-gap after-leak cases: {report.get('known_gap_leaked_after', 0)}",
            f"- Known-gap would-fail cases: {report.get('known_gap_would_fail', 0)}",
            f"- Sensitive values before: {report.get('sensitive_values_leaked_before', 0)}",
            f"- Sensitive values after: {report.get('sensitive_values_leaked_after', 0)}",
            f"- Audit raw-value violations: {report.get('audit_raw_value_violations', 0)}",
            "",
        ]
    )
    _add_summary_table(lines, "By Category", report, "by_category")
    _add_summary_table(lines, "By Surface", report, "by_surface")
    _add_count_table(lines, "By Action", report, "by_action")
    _add_count_table(lines, "By Entity", report, "by_entity")
    _add_count_table(lines, "By Detector Family", report, "by_detector_family")
    _add_case_section(lines, "Failures", report, "failures", "No failing cases.")
    _add_case_section(lines, "Known Gap Would-Fail Cases", report, "would_failures", "No known-gap misses.")
    return "\n".join(lines).rstrip() + "\n"


def format_detector_comparison_markdown(report: dict[str, Any]) -> str:
    lines = ["# LSDF Detector Comparison", ""]
    lines.extend(
        [
            f"- Dataset: {report.get('dataset', 'unknown')}",
            f"- Profile: {report.get('profile', 'unknown')}",
            f"- Mode: {report.get('mode', 'unknown')}",
            f"- Cases: {report.get('case_count', 0)}",
            "",
            "| Set | Status | Families | Passed | Failed | Eval Errors | Blocked | Misses | Known-Gap Misses | Unwanted Mutations | Unwanted Blocks | Known-Gap Leaks | Known-Gap Would-Fail | After-Leak Cases | After-Leak Values | Audit Violations |",
            "| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for result in report.get("detector_sets", []):
        lines.append(
            "| "
            f"{_cell(result.get('name', 'unknown'))} | "
            f"{_cell(result.get('status', 'unknown'))} | "
            f"{_cell(', '.join(result.get('families', [])))} | "
            f"{result.get('passed', 0)} | "
            f"{result.get('failed', 0)} | "
            f"{result.get('evaluation_errors', 0)} | "
            f"{result.get('blocked', 0)} | "
            f"{result.get('misses', 0)} | "
            f"{result.get('known_gap_misses', 0)} | "
            f"{result.get('unwanted_mutations', 0)} | "
            f"{result.get('unwanted_blocks', 0)} | "
            f"{result.get('known_gap_leaked_after', 0)} | "
            f"{result.get('known_gap_would_fail', 0)} | "
            f"{result.get('cases_with_sensitive_values_after', 0)} | "
            f"{result.get('sensitive_values_leaked_after', 0)} | "
            f"{result.get('audit_raw_value_violations', 0)} |"
        )
    lines.append("")
    _add_unavailable_detector_sets(lines, report)
    _add_detector_set_failures(lines, report)
    return "\n".join(lines).rstrip() + "\n"


def _add_summary_table(
    lines: list[str], title: str, report: dict[str, Any], summary_key: str
) -> None:
    rows = report.get("summary", {}).get(summary_key, {})
    lines.extend([f"## {title}", ""])
    if not rows:
        lines.extend(["No data.", ""])
        return
    lines.extend(
        [
            "| Key | Cases | Passed | Failed | Known Gaps | After-Leak Cases | After-Leak Values |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for key in sorted(rows):
        row = rows[key]
        lines.append(
            "| "
            f"{_cell(key)} | {row.get('cases', 0)} | {row.get('passed', 0)} | "
            f"{row.get('failed', 0)} | {row.get('known_gap', 0)} | "
            f"{row.get('cases_with_sensitive_values_after', 0)} | "
            f"{row.get('sensitive_values_leaked_after', 0)} |"
        )
    lines.append("")


def _add_count_table(
    lines: list[str], title: str, report: dict[str, Any], summary_key: str
) -> None:
    rows = report.get("summary", {}).get(summary_key, {})
    lines.extend([f"## {title}", ""])
    if not rows:
        lines.extend(["No data.", ""])
        return
    lines.extend(["| Key | Count |", "| --- | ---: |"])
    for key in sorted(rows):
        lines.append(f"| {_cell(key)} | {rows[key]} |")
    lines.append("")


def _add_case_section(
    lines: list[str], title: str, report: dict[str, Any], key: str, empty: str
) -> None:
    rows = [result for result in report.get("results", []) if result.get(key)]
    lines.extend([f"## {title}", ""])
    if not rows:
        lines.extend([empty, ""])
        return
    for result in rows[:10]:
        lines.append(f"- `{result.get('id')}`: {'; '.join(result.get(key, []))}")
    if len(rows) > 10:
        lines.append(f"- ... {len(rows) - 10} more")
    lines.append("")


def _cell(value: Any) -> str:
    return str(value).replace("|", "\\|")


def _add_unavailable_detector_sets(lines: list[str], report: dict[str, Any]) -> None:
    rows = [
        result
        for result in report.get("detector_sets", [])
        if result.get("status") == "unavailable"
    ]
    lines.extend(["## Unavailable Sets", ""])
    if not rows:
        lines.extend(["No unavailable detector sets.", ""])
        return
    for result in rows:
        lines.append(f"- `{result.get('name')}`: {result.get('reason')}")
    lines.append("")


def _add_detector_set_failures(lines: list[str], report: dict[str, Any]) -> None:
    rows = [
        result
        for result in report.get("detector_sets", [])
        if result.get("status") == "ok" and result.get("failed", 0)
    ]
    lines.extend(["## Failing Sets", ""])
    if not rows:
        lines.extend(["No failing detector sets.", ""])
        return
    for result in rows:
        lines.append(f"- `{result.get('name')}`: {result.get('failed')} failing cases")
    lines.append("")
