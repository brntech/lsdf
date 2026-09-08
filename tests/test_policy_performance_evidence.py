import io
import json
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from lsdf.cli import main
from lsdf.security_ops import (
    _add_performance_section, _format_policy_performance_text, _performance_for_profile,
)


PERFORMANCE_FIXTURE = """## Profile `default`
Detector families: regex. Mode: `redact`.

| Payload | Sample ms (n=1) |
| --- | ---: |
| `small_chat_turn` | 9.657 |
| `rag_heavy_session` | 56.695 |

### Streaming per-chunk inspection
| Stream case | Chunks | Samples | per-chunk p50 | p95 | p99 | max | end-to-end p50 | p95 | max |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `stream_case` | 22 | 110 | 0.196 | 0.297 | 0.346 | 0.420 | 4.291 | 4.661 | 4.752 |

## Profile `balanced`
Detector families: regex. Mode: `redact`.

| Payload | Throughput/sec | min ms | p50 ms | p95 ms | p99 ms | max ms | avg ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `small_chat_turn` | 125 | 4 | 6 | 9 | 10 | 12 | 8 |
"""


class PolicyPerformanceEvidenceTests(unittest.TestCase):
    def setUp(self):
        scratch = TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.path = Path(scratch.name, "performance.md")
        self.path.write_text(PERFORMANCE_FIXTURE, encoding="utf-8")

    def test_cli_single_samples_are_not_reported_as_percentiles_or_throughput(self):
        def performance(profile):
            return _performance_for_profile(profile, self.path)

        for output_format in ("json", "text", "markdown"):
            with self.subTest(format=output_format), patch("lsdf.security_ops._performance_for_profile", side_effect=performance):
                with redirect_stdout(io.StringIO()) as output:
                    status = main(["policy", "explain", "--profile", "default", "--format", output_format])
                self.assertEqual(status, 0)
                body = output.getvalue()
                self.assertNotIn("p50", body)
                self.assertNotIn("throughput_per_sec", body)
                self.assertNotIn("stream_case", body)
                if output_format == "json":
                    report = json.loads(body)["performance"]
                    self.assertEqual(report["payloads"]["small_chat_turn"], {"sample_ms": 9.657, "sample_count": 1})
                    self.assertEqual(len(report["payloads"]), 2)
                else:
                    self.assertIn("n=1", body)
                    self.assertIn("9.657", body)

    def test_legacy_multi_sample_distribution_remains_available(self):
        report = _performance_for_profile("balanced", self.path)
        self.assertTrue(report["available"])
        self.assertEqual(report["payloads"]["small_chat_turn"]["p50_ms"], 6.0)
        self.assertEqual(report["payloads"]["small_chat_turn"]["throughput_per_sec"], 125.0)
        self.assertNotIn("sample_ms", report["payloads"]["small_chat_turn"])
        self.assertIn("p50=6.000", _format_policy_performance_text(report))
        lines = []
        _add_performance_section(lines, report)
        self.assertIn("| Payload | p50 ms | p95 ms | p99 ms |", lines)
        self.assertNotIn("Sample ms", "\n".join(lines))

    def test_malformed_sample_rows_cannot_fall_through_into_stream_distribution(self):
        self.path.write_text(PERFORMANCE_FIXTURE.replace("9.657", "unavailable").replace("56.695", "unavailable"), encoding="utf-8")
        report = _performance_for_profile("default", self.path)
        self.assertFalse(report["available"])
