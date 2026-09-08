import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from lsdf.latency_suite import _benchmark_payload, format_latency_suite_markdown


def _report(case):
    distribution = {"min": 1.0, "p50": 2.0, "p95": 3.0, "p99": 4.0, "max": 5.0, "avg": 2.5}
    return {
        "generated_at": "synthetic-test",
        "iterations_per_case": case["iterations"],
        "payloads": [{"name": "example", "size_bytes": 2, "description": "Synthetic test"}],
        "profiles": [{
            "profile": "default", "available": True, "detector_families": ["regex"], "mode": "redact",
            "cases": [{"name": "example", **case}],
            "streaming_cases": [{
                "name": "stream", "chunks_per_iteration": 2, "per_chunk_sample_count": 6,
                "per_chunk_latency_ms": distribution, "end_to_end_latency_ms": distribution,
            }],
        }],
    }


class LatencyReportTests(unittest.TestCase):
    def test_recorded_report_table_widths_are_valid(self):
        for name in ("docs/performance.md", "EVAL.md", "docs/comparative-protection.md",
                     "docs/measured-protection.md", "docs/detector-composition.md"):
            width = None
            for number, line in enumerate(Path(name).read_text(encoding="utf-8").splitlines(), 1):
                if not line.startswith("|"):
                    width = None
                    continue
                cells = line.count("|") - 1
                if width is None:
                    width = cells
                self.assertEqual(cells, width, f"{name}:{number}: table row width differs from header")

    def test_single_payload_sample_is_not_a_distribution_or_rate(self):
        firewall = SimpleNamespace(inspect=Mock())
        with patch("lsdf.latency_suite.time.perf_counter", side_effect=[1.0, 1.0025]):
            case = _benchmark_payload(firewall, {}, iterations=1)
        self.assertEqual(case["iterations"], 1)
        self.assertEqual(set(case["latency_ms"]), {"sample"})
        self.assertAlmostEqual(case["latency_ms"]["sample"], 2.5)
        self.assertNotIn("throughput_per_second", case)
        body = format_latency_suite_markdown(_report(case))
        payload_section = body.split("### Streaming per-chunk inspection")[0]
        self.assertIn("| Payload | Sample ms (n=1) |", payload_section)
        self.assertIn("| `example` | 2.500 |", payload_section)
        self.assertNotIn("| p50 |", payload_section)
        self.assertNotIn("calls/sec", payload_section)
        self.assertIn("| Stream case | Chunks | Samples | per-chunk p50", body)
        self.assertIn("| `stream` | 2 | 6 |", body)

    def test_repeated_payloads_retain_measured_distribution(self):
        firewall = SimpleNamespace(inspect=Mock())
        with patch("lsdf.latency_suite.time.perf_counter", side_effect=[1.0, 1.001, 2.0, 2.003]):
            case = _benchmark_payload(firewall, {}, iterations=2)
        self.assertEqual(firewall.inspect.call_count, 2)
        self.assertEqual(set(case["latency_ms"]), {"min", "p50", "p95", "p99", "max", "avg"})
        self.assertAlmostEqual(case["latency_ms"]["p50"], 2.0)
        body = format_latency_suite_markdown(_report(case))
        self.assertIn("| Payload | Measured calls/sec | min | p50 | p95 | p99 | max | avg |", body)
        self.assertNotIn("| Payload | Sample ms", body)
        self.assertIn("No warmup samples are discarded", body)
        self.assertNotIn("steady-state after warmup", body)

    def test_reproduce_commands_use_cli_and_separate_scratch_outputs(self):
        body = format_latency_suite_markdown(_report({"iterations": 1, "latency_ms": {"sample": 1.0}}))
        self.assertIn("docker compose run --rm cli latency-table --profile default --profile balanced", body)
        self.assertIn("optional-cli latency-table --profile default --profile balanced --profile broad-pii --profile broad-pii-ml", body)
        self.assertIn("performance-default-balanced.md.tmp && mv", body)
        self.assertIn("performance-full-matrix.md.tmp && mv", body)
        self.assertNotIn("run --rm test python", body)
        self.assertNotIn("2>/dev/null", body)
        self.assertNotIn("> docs/performance.md", body)


if __name__ == "__main__":
    unittest.main()
