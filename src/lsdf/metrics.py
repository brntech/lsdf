# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from threading import Lock
from typing import Any


@dataclass
class MetricBucket:
    count: int = 0
    total_ms: float = 0.0
    min_ms: float | None = None
    max_ms: float | None = None

    def add(self, duration_ms: float) -> None:
        self.count += 1
        self.total_ms += duration_ms
        self.min_ms = duration_ms if self.min_ms is None else min(self.min_ms, duration_ms)
        self.max_ms = duration_ms if self.max_ms is None else max(self.max_ms, duration_ms)

    def to_dict(self) -> dict[str, Any]:
        avg = self.total_ms / self.count if self.count else 0.0
        return {
            "count": self.count,
            "total_ms": self.total_ms,
            "min_ms": self.min_ms or 0.0,
            "max_ms": self.max_ms or 0.0,
            "avg_ms": avg,
        }


@dataclass
class MetricsSnapshot:
    counters: dict[str, int] = field(default_factory=dict)
    durations: dict[str, MetricBucket] = field(default_factory=dict)


class MetricsRecorder:
    def __init__(self, *, enabled: bool = True, jsonl_path: str | Path | None = None):
        self.enabled = enabled
        self.jsonl_path = Path(jsonl_path) if jsonl_path else None
        self._snapshot = MetricsSnapshot()
        self._lock = Lock()

    def increment(self, name: str, amount: int = 1, **labels: Any) -> None:
        if not self.enabled:
            return
        key = _metric_key(name, labels)
        with self._lock:
            self._snapshot.counters[key] = self._snapshot.counters.get(key, 0) + amount
        self._write_event({"type": "counter", "name": name, "amount": amount, "labels": _safe_labels(labels)})

    def observe_ms(self, name: str, duration_ms: float, **labels: Any) -> None:
        if not self.enabled:
            return
        key = _metric_key(name, labels)
        with self._lock:
            bucket = self._snapshot.durations.setdefault(key, MetricBucket())
            bucket.add(duration_ms)
        self._write_event({"type": "duration", "name": name, "duration_ms": duration_ms, "labels": _safe_labels(labels)})

    def time_ms(self, name: str, **labels: Any):
        return _MetricTimer(self, name, labels)

    def to_dict(self) -> dict[str, Any]:
        with self._lock:
            return {
                "counters": dict(sorted(self._snapshot.counters.items())),
                "durations": {
                    key: bucket.to_dict()
                    for key, bucket in sorted(self._snapshot.durations.items())
                },
            }

    def prometheus_text(self) -> str:
        snapshot = self.to_dict()
        lines: list[str] = []
        for key, value in snapshot["counters"].items():
            lines.append(f"lsdf_{_sanitize_metric_name(key)} {value}")
        for key, bucket in snapshot["durations"].items():
            base = f"lsdf_{_sanitize_metric_name(key)}"
            lines.append(f"{base}_count {bucket['count']}")
            lines.append(f"{base}_sum_ms {bucket['total_ms']:.6f}")
            lines.append(f"{base}_avg_ms {bucket['avg_ms']:.6f}")
            lines.append(f"{base}_max_ms {bucket['max_ms']:.6f}")
        return "\n".join(lines).rstrip() + "\n"

    def _write_event(self, event: dict[str, Any]) -> None:
        if self.jsonl_path is None:
            return
        try:
            self.jsonl_path.parent.mkdir(parents=True, exist_ok=True)
            payload = {"timestamp": time.time(), **event}
            with self.jsonl_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(payload, separators=(",", ":")) + "\n")
        except Exception:
            return


class _MetricTimer:
    def __init__(self, recorder: MetricsRecorder, name: str, labels: dict[str, Any]):
        self.recorder = recorder
        self.name = name
        self.labels = labels
        self.started = 0.0

    def __enter__(self):
        self.started = time.perf_counter()
        return self

    def __exit__(self, exc_type, exc, tb):
        duration_ms = (time.perf_counter() - self.started) * 1000
        labels = dict(self.labels)
        if exc_type is not None:
            labels["error_type"] = exc_type.__name__
        self.recorder.observe_ms(self.name, duration_ms, **labels)
        return False


def summarize_metrics_jsonl(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"Metrics JSONL not found: {path}")
    summary: dict[str, Any] = {
        "path": str(path),
        "event_count": 0,
        "malformed_lines": 0,
        "by_type": {},
        "by_name": {},
        "by_label": {},
        "duration_ms": {},
    }
    durations: dict[str, list[float]] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            summary["malformed_lines"] += 1
            continue
        summary["event_count"] += 1
        _increment(summary["by_type"], event.get("type", "unknown"))
        name = str(event.get("name", "unknown"))
        _increment(summary["by_name"], name)
        for key, value in (event.get("labels") or {}).items():
            _increment(summary["by_label"], f"{key}={value}")
        if event.get("type") == "duration":
            durations.setdefault(name, []).append(float(event.get("duration_ms", 0.0)))
    for name, values in durations.items():
        ordered = sorted(values)
        summary["duration_ms"][name] = {
            "count": len(values),
            "min": ordered[0],
            "p50": _percentile(ordered, 50),
            "p95": _percentile(ordered, 95),
            "max": ordered[-1],
            "avg": sum(values) / len(values),
        }
    return summary


def format_metrics_summary_text(summary: dict[str, Any]) -> str:
    lines = [
        "LSDF Metrics Summary",
        f"- Path: {summary['path']}",
        f"- Events: {summary['event_count']}",
        f"- Malformed lines: {summary['malformed_lines']}",
        _format_counts("Types", summary["by_type"]),
        _format_counts("Names", summary["by_name"]),
        _format_counts("Labels", summary["by_label"]),
    ]
    return "\n".join(lines) + "\n"


def format_metrics_summary_markdown(summary: dict[str, Any]) -> str:
    lines = [
        "# LSDF Metrics Summary",
        "",
        f"- Path: {summary['path']}",
        f"- Events: {summary['event_count']}",
        f"- Malformed lines: {summary['malformed_lines']}",
        "",
        "| Name | Count | Avg ms | P95 ms | Max ms |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for name, bucket in sorted(summary.get("duration_ms", {}).items()):
        lines.append(
            f"| {name} | {bucket['count']} | {bucket['avg']:.3f} | {bucket['p95']:.3f} | {bucket['max']:.3f} |"
        )
    return "\n".join(lines).rstrip() + "\n"


def _metric_key(name: str, labels: dict[str, Any]) -> str:
    if not labels:
        return name
    suffix = ",".join(f"{key}={labels[key]}" for key in sorted(labels))
    return f"{name}{{{suffix}}}"


def _safe_labels(labels: dict[str, Any]) -> dict[str, Any]:
    safe: dict[str, Any] = {}
    for key, value in labels.items():
        if value is None:
            continue
        if isinstance(value, (int, float, bool)):
            safe[key] = value
        else:
            safe[key] = str(value)
    return safe


def _sanitize_metric_name(value: str) -> str:
    return "".join(char if char.isalnum() else "_" for char in value).strip("_")


def _increment(mapping: dict[str, int], key: Any) -> None:
    text = str(key)
    mapping[text] = mapping.get(text, 0) + 1


def _format_counts(title: str, mapping: dict[str, int]) -> str:
    if not mapping:
        return f"- {title}: none"
    items = ", ".join(f"{key}={value}" for key, value in sorted(mapping.items()))
    return f"- {title}: {items}"


def _percentile(values: list[float], percentile: int) -> float:
    if not values:
        return 0.0
    index = min(len(values) - 1, round((percentile / 100) * (len(values) - 1)))
    return values[index]
