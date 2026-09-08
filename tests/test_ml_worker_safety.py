# SPDX-License-Identifier: Apache-2.0
"""Worker protocol regressions use owned synthetic processes, never ML models."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stdout
from io import StringIO
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
from tempfile import TemporaryDirectory
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from lsdf.detectors import build_detector_registry
from lsdf.scanners import openai_privacy_filter as privacy_filter
from lsdf.scanners import openai_privacy_filter_worker as worker


RAW_MARKER = "owned-example-must-not-appear-in-diagnostics"
SYNTHETIC_WORKER = r"""
import json, os, sys, time
mode = sys.argv[1]
marker = "owned-example-must-not-appear-in-diagnostics"
def emit(value):
    print(json.dumps(value), flush=True)
if mode == "startup_hang":
    time.sleep(60)
if mode == "startup_error":
    emit({"error": marker})
    raise SystemExit(1)
if mode == "stderr":
    os.write(2, (marker * 20000).encode())
emit({"status": "ready", "metadata": {"synthetic": True}})
if mode == "write_hang":
    time.sleep(60)
for line in sys.stdin:
    request = json.loads(line)
    request_id = request["request_id"]
    if mode == "read_hang":
        time.sleep(60)
    if mode == "slow":
        time.sleep(0.35)
    if mode == "stderr":
        os.write(2, (marker * 20000).encode())
    if mode == "error_once" and request_id == 1:
        emit({"request_id": request_id, "error": marker})
        continue
    if mode == "bad_error":
        emit({"request_id": request_id, "error": {"detail": marker}})
        continue
    if mode == "error_and_results":
        emit({"request_id": request_id, "error": marker, "results": []})
        continue
    if mode == "bad_json":
        print(marker, flush=True)
        continue
    if mode == "eof":
        os.write(2, marker.encode())
        raise SystemExit(1)
    if mode == "oversized":
        print("x" * (8 * 1024 * 1024 + 1), flush=True)
        continue
    offset = request["text"].index("TAG")
    reply = {
        "request_id": request_id + (100 if mode == "wrong_id" else 0),
        "results": [{"entity": "private_person", "start": offset,
                     "end": offset + 3, "score": 1.0}],
    }
    emit(reply)
    if mode == "stale":
        emit(reply)
"""


class WorkerProcessTests(unittest.TestCase):
    def setUp(self):
        # Also bound the regressions themselves if a blocking-I/O bug returns.
        self.previous_alarm = signal.signal(
            signal.SIGALRM, lambda *_: self.fail("Synthetic worker test deadline")
        )
        signal.alarm(15)
        self.real_popen = subprocess.Popen
        self.processes = []
        self.providers = []
        self.modes = ["normal"]
        # Replace only this adapter's module reference, not process-wide Popen.
        self.popen_patch = patch.object(
            privacy_filter, "subprocess", SimpleNamespace(
                Popen=self.spawn_worker,
                PIPE=subprocess.PIPE,
                DEVNULL=subprocess.DEVNULL,
                TimeoutExpired=subprocess.TimeoutExpired,
            )
        )
        self.popen_patch.start()

    def tearDown(self):
        # Kill first so even a failed assertion in a timeout test cannot orphan.
        for process in self.processes:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=2)
        for provider in self.providers:
            provider.close()
        self.popen_patch.stop()
        signal.alarm(0)
        signal.signal(signal.SIGALRM, self.previous_alarm)

    def spawn_worker(self, args, **kwargs):
        mode = self.modes.pop(0) if len(self.modes) > 1 else self.modes[0]
        process = self.real_popen(
            [sys.executable, "-u", "-c", SYNTHETIC_WORKER, mode], **kwargs
        )
        self.processes.append(process)
        return process

    def provider(self, **kwargs):
        provider = privacy_filter.SubprocessPrivacyFilterProvider(
            python_executable=sys.executable,
            model_name="owned-synthetic",
            local_files_only=True,
            startup_timeout_seconds=kwargs.pop("startup_timeout_seconds", 2),
            inference_timeout_seconds=kwargs.pop("inference_timeout_seconds", 2),
            **kwargs,
        )
        self.providers.append(provider)
        return provider

    def assert_reset(self, provider):
        self.assertIsNone(provider.process)
        self.assertIsNone(provider.startup_metadata)
        self.assertEqual(provider._stdout_buffer, b"")
        self.assertIsNotNone(self.processes[-1].poll())
        self.assertTrue(self.processes[-1].stdin.closed)
        self.assertTrue(self.processes[-1].stdout.closed)

    def test_concurrent_cold_start_and_requests_keep_own_spans(self):
        provider = self.provider()
        barrier = threading.Barrier(12)

        def scan(offset):
            barrier.wait(timeout=3)
            results = provider("x" * offset + "TAG")
            return results[0]["start"], results[0]["end"]

        with ThreadPoolExecutor(max_workers=12) as pool:
            results = list(pool.map(scan, range(12)))
        self.assertEqual(results, [(offset, offset + 3) for offset in range(12)])
        self.assertEqual(len(self.processes), 1)

    def test_second_request_cannot_write_while_first_awaits_response(self):
        provider = self.provider()
        provider._ensure_process()
        reading = threading.Event()
        release_read = threading.Event()
        second_write = threading.Event()
        read = provider._read_message
        write = provider._write_request
        first_read = True

        def hold_first_read(*args):
            nonlocal first_read
            if first_read:
                first_read = False
                reading.set()
                self.assertTrue(release_read.wait(timeout=2))
            return read(*args)

        def observe_write(process, request, deadline):
            if json.loads(request)["text"] == "xxxxxTAG":
                second_write.set()
            write(process, request, deadline)

        with patch.object(provider, "_read_message", side_effect=hold_first_read):
            with patch.object(provider, "_write_request", side_effect=observe_write):
                with ThreadPoolExecutor(max_workers=2) as pool:
                    first = pool.submit(provider, "TAG")
                    try:
                        self.assertTrue(reading.wait(timeout=2))
                        second = pool.submit(provider, "xxxxxTAG")
                        self.assertFalse(second_write.wait(timeout=0.1))
                    finally:
                        release_read.set()
                    self.assertEqual(first.result(timeout=2)[0]["start"], 0)
                    self.assertEqual(second.result(timeout=2)[0]["start"], 5)
        self.assertTrue(second_write.is_set())

    def test_concurrent_recreation_uses_one_replacement(self):
        provider = self.provider()
        old = provider._ensure_process()
        old.kill()
        old.wait(timeout=2)
        barrier = threading.Barrier(8)

        def ensure(_):
            barrier.wait(timeout=3)
            return provider._ensure_process()

        with ThreadPoolExecutor(max_workers=8) as pool:
            processes = list(pool.map(ensure, range(8)))
        self.assertTrue(all(process is processes[0] for process in processes))
        self.assertEqual(len(self.processes), 2)
        self.assertTrue(old.stdin.closed)
        self.assertTrue(old.stdout.closed)

    def test_startup_timeout_reaps_and_can_restart(self):
        self.modes = ["startup_hang", "normal"]
        provider = self.provider(startup_timeout_seconds=0.2)
        started = time.monotonic()
        with self.assertRaisesRegex(RuntimeError, r"startup failed \(timeout\)"):
            provider._ensure_process()
        self.assertLess(time.monotonic() - started, 3)
        self.assert_reset(provider)
        self.assertEqual(provider("TAG")[0]["start"], 0)

    def test_response_timeout_reaps_and_cannot_reuse_old_response(self):
        self.modes = ["read_hang", "normal"]
        provider = self.provider(inference_timeout_seconds=0.2)
        with self.assertRaisesRegex(RuntimeError, r"inference failed \(timeout\)"):
            provider("TAG")
        self.assert_reset(provider)
        self.assertEqual(provider("xxxxxTAG")[0]["start"], 5)
        self.assertEqual(len(self.processes), 2)

    def test_blocked_request_write_is_bounded(self):
        self.modes = ["write_hang"]
        provider = self.provider(inference_timeout_seconds=0.2)
        started = time.monotonic()
        with self.assertRaisesRegex(RuntimeError, r"inference failed \(timeout\)"):
            provider("x" * (1024 * 1024) + "TAG")
        self.assertLess(time.monotonic() - started, 3)
        self.assert_reset(provider)

    def test_queue_timeout_does_not_kill_active_request(self):
        self.modes = ["slow"]
        provider = self.provider()
        process = provider._ensure_process()
        written = threading.Event()
        write = provider._write_request

        def notify_write(*args):
            write(*args)
            written.set()

        with patch.object(provider, "_write_request", side_effect=notify_write):
            with ThreadPoolExecutor(max_workers=1) as pool:
                active = pool.submit(provider, "xxxTAG")
                self.assertTrue(written.wait(timeout=2))
                # The active request already captured its 2-second budget.
                provider.inference_timeout_seconds = 0.08
                with self.assertRaisesRegex(RuntimeError, "queue timeout"):
                    provider("TAG")
                self.assertIs(provider.process, process)
                self.assertIsNone(process.poll())
                self.assertEqual(active.result(timeout=2)[0]["start"], 3)

    def test_queue_wait_consumes_inference_budget(self):
        provider = self.provider(inference_timeout_seconds=0.4)
        provider._ensure_process()
        provider._lock.acquire()
        entered = threading.Event()
        deadlines = []
        write = provider._write_request
        serialized = provider._serialized

        def observe_queue(timeout):
            entered.set()
            return serialized(timeout)

        def observe_write(process, request, deadline):
            deadlines.append(deadline - time.monotonic())
            write(process, request, deadline)

        with patch.object(provider, "_serialized", side_effect=observe_queue):
            with patch.object(provider, "_write_request", side_effect=observe_write):
                with ThreadPoolExecutor(max_workers=1) as pool:
                    result = pool.submit(provider, "TAG")
                    try:
                        self.assertTrue(entered.wait(timeout=2))
                        time.sleep(0.15)
                    finally:
                        provider._lock.release()
                    self.assertEqual(result.result(timeout=2)[0]["start"], 0)
        self.assertGreater(deadlines[0], 0)
        self.assertLess(deadlines[0], 0.30)

    def test_close_waits_for_active_exchange_and_reaps(self):
        self.modes = ["slow"]
        provider = self.provider()
        process = provider._ensure_process()
        written = threading.Event()
        write = provider._write_request

        def notify_write(*args):
            write(*args)
            written.set()

        with patch.object(provider, "_write_request", side_effect=notify_write):
            with ThreadPoolExecutor(max_workers=2) as pool:
                active = pool.submit(provider, "xxTAG")
                self.assertTrue(written.wait(timeout=2))
                closed = pool.submit(provider.close)
                self.assertEqual(active.result(timeout=2)[0]["start"], 2)
                closed.result(timeout=2)
        self.assertIsNone(provider.process)
        self.assertIsNotNone(process.poll())

    def test_stderr_flood_cannot_block_startup_or_inference(self):
        self.modes = ["stderr"]
        provider = self.provider()
        self.assertEqual(provider("TAG")[0]["start"], 0)
        self.assertIsNone(provider.process.stderr)

    def test_model_error_keeps_synchronized_worker_for_next_request(self):
        self.modes = ["error_once"]
        provider = self.provider()
        process = provider._ensure_process()
        with self.assertRaisesRegex(RuntimeError, r"inference failed \(model error\)") as caught:
            provider("TAG")
        self.assertNotIn(RAW_MARKER, str(caught.exception))
        self.assertTrue(caught.exception.__suppress_context__)
        self.assertIs(provider.process, process)
        self.assertIsNone(process.poll())
        self.assertEqual(provider("xxxxTAG")[0]["start"], 4)
        self.assertIs(provider.process, process)
        self.assertEqual(len(self.processes), 1)

    def test_worker_mock_does_not_replace_global_popen(self):
        self.provider()._ensure_process()
        self.assertIs(subprocess.Popen, self.real_popen)

    def test_invalid_responses_are_safe_and_reset(self):
        for mode in ("bad_error", "error_and_results", "bad_json", "wrong_id", "eof", "oversized"):
            with self.subTest(mode=mode):
                self.modes = [mode]
                provider = self.provider()
                with self.assertRaises(RuntimeError) as caught:
                    provider("TAG")
                self.assertIn("inference failed", str(caught.exception))
                self.assertNotIn(RAW_MARKER, str(caught.exception))
                self.assertTrue(caught.exception.__suppress_context__)
                self.assert_reset(provider)

    def test_startup_error_does_not_expose_worker_payload(self):
        self.modes = ["startup_error"]
        provider = self.provider()
        with self.assertRaises(RuntimeError) as caught:
            provider._ensure_process()
        self.assertNotIn(RAW_MARKER, str(caught.exception))
        self.assertTrue(caught.exception.__suppress_context__)
        self.assert_reset(provider)

    def test_extra_stale_response_cannot_be_used_for_next_request(self):
        self.modes = ["stale", "normal"]
        provider = self.provider()
        self.assertEqual(provider("TAG")[0]["start"], 0)
        with self.assertRaisesRegex(RuntimeError, "invalid response"):
            provider("xxxxTAG")
        self.assert_reset(provider)
        self.assertEqual(provider("xxxxTAG")[0]["start"], 4)


class WorkerConfigurationTests(unittest.TestCase):
    def test_deadlines_default_and_env_and_explicit_precedence(self):
        for env, expected in (
            ({}, (300.0, 60.0)),
            ({
                "LSDF_OPENAI_PRIVACY_FILTER_STARTUP_TIMEOUT_SECONDS": "",
                "LSDF_OPENAI_PRIVACY_FILTER_INFERENCE_TIMEOUT_SECONDS": " \t ",
            }, (300.0, 60.0)),
            ({
                "LSDF_OPENAI_PRIVACY_FILTER_STARTUP_TIMEOUT_SECONDS": "12.5",
                "LSDF_OPENAI_PRIVACY_FILTER_INFERENCE_TIMEOUT_SECONDS": "4.5",
            }, (12.5, 4.5)),
        ):
            with self.subTest(env=bool(env)), patch.dict(os.environ, env, clear=True):
                with patch.object(privacy_filter, "_privacy_filter_worker_python", return_value=sys.executable):
                    with patch.object(privacy_filter.SubprocessPrivacyFilterProvider, "_ensure_process"):
                        detector = privacy_filter.build_installed_openai_privacy_filter_detector()
                        self.assertEqual(
                            (detector.provider.startup_timeout_seconds,
                             detector.provider.inference_timeout_seconds), expected
                        )
                        explicit = privacy_filter.build_installed_openai_privacy_filter_detector(
                            startup_timeout_seconds=7, inference_timeout_seconds=3
                        )
                        self.assertEqual(explicit.provider.startup_timeout_seconds, 7)
                        self.assertEqual(explicit.provider.inference_timeout_seconds, 3)

    def test_invalid_deadlines_fail_without_echoing_values(self):
        for value in (0, -1, float("nan"), float("inf"), RAW_MARKER, None, "", " \t "):
            for name in ("startup_timeout_seconds", "inference_timeout_seconds"):
                with self.subTest(name=name, value_type=type(value).__name__):
                    with self.assertRaises(ValueError) as caught:
                        privacy_filter.SubprocessPrivacyFilterProvider(
                            sys.executable, "owned-synthetic", True, **{name: value}
                        )
                    self.assertNotIn(RAW_MARKER, str(caught.exception))

    def test_optional_model_configuration_errors_remain_fatal(self):
        for name in (
            "LSDF_OPENAI_PRIVACY_FILTER_STARTUP_TIMEOUT_SECONDS",
            "LSDF_OPENAI_PRIVACY_FILTER_INFERENCE_TIMEOUT_SECONDS",
        ):
            for value in ("0", "-1", "nan", "inf", RAW_MARKER):
                with self.subTest(setting=name, value_kind="invalid"):
                    with patch.dict(os.environ, {
                        "LSDF_OPENAI_PRIVACY_FILTER_PYTHON": sys.executable,
                        name: value,
                    }, clear=True):
                        with self.assertRaises(ValueError) as caught:
                            build_detector_registry(
                                ("openai_privacy_filter",),
                                detector_settings={"openai_privacy_filter": {"required": False}},
                            )
                        self.assertNotIn(RAW_MARKER, str(caught.exception))
        with patch.dict(os.environ, {
            "LSDF_OPENAI_PRIVACY_FILTER_PYTHON": "/missing/owned-interpreter",
        }, clear=True):
            with self.assertRaises(ValueError):
                build_detector_registry(
                    ("openai_privacy_filter",),
                    detector_settings={"openai_privacy_filter": {"required": False}},
                )

    def test_complete_buffered_reply_wins_over_expired_wait_deadline(self):
        provider = privacy_filter.SubprocessPrivacyFilterProvider(
            sys.executable, "owned-synthetic", True
        )
        process = SimpleNamespace(stdout=object())
        provider._stdout_buffer.extend(b'{"request_id": 1, "results": []}\n{"partial":')
        with patch.object(provider, "_wait_for_pipe") as wait:
            self.assertEqual(
                provider._read_message(process, deadline=time.monotonic() - 1),
                {"request_id": 1, "results": []},
            )
            wait.assert_not_called()
        self.assertEqual(provider._stdout_buffer, b'{"partial":')
        with self.assertRaises(TimeoutError):
            provider._read_message(process, deadline=time.monotonic() - 1)

    def test_invalid_explicit_worker_path_never_falls_back(self):
        with TemporaryDirectory() as directory:
            not_executable = Path(directory, "not-executable")
            not_executable.write_text("owned synthetic text", encoding="utf-8")
            not_executable.chmod(0o600)
            for value in ("", str(Path(directory, "missing")), directory, str(not_executable)):
                with self.subTest(path_kind="invalid"), patch.dict(
                    os.environ, {"LSDF_OPENAI_PRIVACY_FILTER_PYTHON": value}
                ):
                    with self.assertRaisesRegex(ValueError, "must name an executable file"):
                        privacy_filter.build_installed_openai_privacy_filter_detector()

    def test_explicit_valid_worker_path_is_retained(self):
        with patch.dict(os.environ, {"LSDF_OPENAI_PRIVACY_FILTER_PYTHON": sys.executable}):
            self.assertEqual(privacy_filter._privacy_filter_worker_python(), sys.executable)


class ActualWorkerProtocolTests(unittest.TestCase):
    def invoke(self, lines, *, initialization_error=False):
        def load(*args, **kwargs):
            if initialization_error:
                raise RuntimeError(RAW_MARKER)
            return object()

        def classify(text):
            if text == "fail":
                raise RuntimeError(RAW_MARKER)
            return [{"entity": "private_person", "start": 0, "end": 3, "score": 1.0}]

        fake_transformers = SimpleNamespace(
            AutoModelForTokenClassification=SimpleNamespace(from_pretrained=load),
            AutoTokenizer=SimpleNamespace(from_pretrained=load),
            pipeline=lambda *args, **kwargs: classify,
        )
        output = StringIO()
        with patch.dict(sys.modules, {"transformers": fake_transformers}):
            with patch.object(sys, "argv", ["worker", "--model-name", "owned-synthetic"]):
                with patch.object(sys, "stdin", StringIO("\n".join(lines) + "\n")):
                    with redirect_stdout(output):
                        status = worker.main()
        self.assertNotIn(RAW_MARKER, output.getvalue())
        return status, [json.loads(line) for line in output.getvalue().splitlines()]

    def test_actual_worker_echoes_ids_and_uses_static_errors(self):
        status, output = self.invoke([
            json.dumps({"request_id": 9, "text": "TAG"}),
            json.dumps({"request_id": 10, "text": "fail"}),
            json.dumps({"request_id": RAW_MARKER, "text": "TAG"}),
            RAW_MARKER,
            json.dumps({"request_id": 11, "text": None}),
        ])
        self.assertEqual(status, 0)
        self.assertEqual(output[0]["status"], "ready")
        self.assertEqual(output[1]["request_id"], 9)
        self.assertEqual(output[1]["results"][0]["start"], 0)
        self.assertEqual(output[2], {"request_id": 10, "error": "inference failed"})
        self.assertEqual(output[3], {"request_id": None, "error": "inference failed"})
        self.assertEqual(output[4], {"request_id": None, "error": "inference failed"})
        self.assertEqual(output[5], {"request_id": 11, "error": "inference failed"})

    def test_actual_worker_initialization_error_is_static(self):
        status, output = self.invoke([], initialization_error=True)
        self.assertEqual(status, 1)
        self.assertEqual(output, [{"error": "model initialization failed"}])


if __name__ == "__main__":
    unittest.main()
