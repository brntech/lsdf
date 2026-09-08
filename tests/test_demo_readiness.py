# SPDX-License-Identifier: Apache-2.0
"""Demo readiness must wait past HTTP 200 responses from a degraded gateway."""

import importlib.util
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import MagicMock, patch

from lsdf import demo_runner


_CLIENT_PATH = (
    Path(__file__).resolve().parents[1]
    / "examples"
    / "integrations"
    / "runnable_client_examples.py"
)
_CLIENT_SPEC = importlib.util.spec_from_file_location(
    "lsdf_readiness_client_examples", _CLIENT_PATH
)
client_examples = importlib.util.module_from_spec(_CLIENT_SPEC)
_CLIENT_SPEC.loader.exec_module(client_examples)


def _response(body):
    response = MagicMock()
    response.__enter__.return_value = response
    response.__exit__.return_value = False
    response.read.return_value = body
    return response


class DemoReadinessTests(unittest.TestCase):
    def test_demo_waits_for_healthy_json_after_transient_and_degraded_responses(self):
        checks = []
        responses = [
            urllib.error.URLError("not ready"),
            b'{"status":"degraded","upstream":{"status":"error"}}',
            b"not-json",
            b"[]",
            b'{"status":"ok","upstream":{"status":"ok"}}',
        ]
        with patch.object(demo_runner, "_get_bytes", side_effect=responses) as get:
            with patch.object(demo_runner.time, "sleep") as sleep:
                demo_runner._wait_for_gateway("http://gateway", checks)
        self.assertEqual(get.call_count, 5)
        get.assert_called_with("http://gateway/lsdf/health")
        self.assertEqual(sleep.call_count, 4)
        sleep.assert_called_with(0.25)
        self.assertEqual(checks, [{"name": "gateway_ready", "status": "ok"}])

    def test_demo_exhausts_attempts_when_http_success_remains_degraded(self):
        checks = []
        with patch.object(
            demo_runner, "_get_bytes", return_value=b'{"status":"degraded"}'
        ) as get:
            with patch.object(demo_runner.time, "sleep") as sleep:
                demo_runner._wait_for_gateway("http://gateway", checks)
        self.assertEqual(get.call_count, 60)
        self.assertEqual(sleep.call_count, 60)
        self.assertEqual(
            checks,
            [{"name": "gateway_ready", "status": "error", "message": "not reachable"}],
        )

    def test_client_waits_for_healthy_json_and_normalizes_v1_base(self):
        responses = [
            urllib.error.URLError("not ready"),
            _response(b'{"status":"degraded","upstream":{"status":"error"}}'),
            _response(b"not-json"),
            _response(b"[]"),
            _response(b'{"status":"ok","upstream":{"status":"ok"}}'),
        ]
        with patch.object(
            client_examples.urllib.request, "urlopen", side_effect=responses
        ) as get:
            with patch.object(client_examples.time, "sleep") as sleep:
                result = client_examples._wait_for_gateway(
                    "http://gateway/v1/", attempts=5, delay_seconds=0.1
                )
        self.assertIsNone(result)
        self.assertEqual(get.call_count, 5)
        get.assert_called_with("http://gateway/lsdf/health", timeout=2)
        self.assertEqual(sleep.call_count, 4)
        sleep.assert_called_with(0.1)

    def test_client_preserves_bounded_fallthrough_when_never_healthy(self):
        with patch.object(
            client_examples.urllib.request,
            "urlopen",
            return_value=_response(b'{"status":"degraded"}'),
        ) as get:
            with patch.object(client_examples.time, "sleep") as sleep:
                result = client_examples._wait_for_gateway(
                    "http://gateway/v1", attempts=3, delay_seconds=0.1
                )
        self.assertIsNone(result)
        self.assertEqual(get.call_count, 3)
        self.assertEqual(sleep.call_count, 3)


if __name__ == "__main__":
    unittest.main()
