# SPDX-License-Identifier: Apache-2.0
import math
import sys
import unittest
from unittest.mock import patch

from lsdf.detectors import DetectorUnavailableError, build_detector_registry
from lsdf.scanners.gliner import GLiNERDetector, _chunk_text
from lsdf.surfaces import Surface


class GLiNERChunkProgressTests(unittest.TestCase):
    def chunks(self, text, max_chars, stride_chars):
        # Fail deterministically instead of hanging if chunk progress regresses.
        previous_trace = sys.gettrace()
        calls = 0

        def trace(frame, event, arg):
            nonlocal calls
            if frame.f_code is _chunk_text.__code__ and event == "line":
                calls += 1
                if calls > 30 * (len(text) + 1):
                    raise AssertionError("Chunk loop did not make forward progress")
            return trace

        sys.settrace(trace)
        try:
            return _chunk_text(text, max_chars=max_chars, stride_chars=stride_chars)
        finally:
            sys.settrace(previous_trace)

    def test_custom_windows_terminate_with_full_coverage(self):
        for max_chars, stride_chars in ((80, 20), (1, 0), (8, 99), (80, 0)):
            for text in ("a " + "b" * 200, "word " * 61, "x" * 301):
                with self.subTest(max_chars=max_chars, stride_chars=stride_chars):
                    chunks = self.chunks(text, max_chars, stride_chars)
                    covered = set()
                    previous_start = -1
                    for start, chunk in chunks:
                        self.assertGreater(start, previous_start)
                        self.assertEqual(chunk, text[start : start + len(chunk)])
                        self.assertLessEqual(len(chunk), max_chars)
                        covered.update(range(start, start + len(chunk)))
                        previous_start = start
                    self.assertEqual(covered, set(range(len(text))))
                    self.assertEqual(chunks[-1][0] + len(chunks[-1][1]), len(text))

    def test_custom_window_boundary_does_not_amplify_inference_calls(self):
        class CountingModel:
            def __init__(self):
                self.calls = 0

            def predict_entities(self, text, labels, *, threshold):
                self.calls += 1
                return []

        for length in (202, 2002):
            with self.subTest(length=length):
                text = "a " + "b" * (length - 2)
                model = CountingModel()
                detector = GLiNERDetector(model, max_chars=80, stride_chars=20)
                self.assertEqual(
                    detector.scan(Surface("output.content", ("content",), text)), []
                )
                # One early alignment may add a window; it must not turn a
                # 60-character step into one model inference per character.
                self.assertLessEqual(model.calls, math.ceil(length / 60) + 1)

    def test_default_windows_keep_existing_boundaries(self):
        text = "x" * 5000
        self.assertEqual(
            [start for start, _ in self.chunks(text, 1400, 350)],
            [0, 1050, 2100, 3150, 4200],
        )
        text = "word " * 1000
        self.assertEqual(
            [start for start, _ in self.chunks(text, 1400, 350)],
            [0, 1050, 2100, 3150, 4200],
        )

    def test_custom_scan_still_finds_tail_span(self):
        class TailModel:
            def predict_entities(self, text, labels, *, threshold):
                start = text.find("TAG")
                return [] if start < 0 else [
                    {"label": "person", "start": start, "end": start + 3, "score": 1.0}
                ]

        text = "a " + "b" * 197 + "TAG"
        detector = GLiNERDetector(TailModel(), max_chars=80, stride_chars=20)
        findings = detector.scan(Surface("output.content", ("content",), text))
        self.assertEqual([(item.start, item.end) for item in findings], [(199, 202)])


class GLiNERRequiredSettingTests(unittest.TestCase):
    def test_optional_unavailable_model_is_skipped(self):
        def unavailable(*, threshold):
            self.assertEqual(threshold, 0.45)
            raise RuntimeError("Synthetic model unavailable")

        with patch("lsdf.scanners.gliner.build_installed_gliner_detector", unavailable):
            registry = build_detector_registry(
                ("gliner",), detector_settings={"gliner": {"required": False, "threshold": 0.45}}
            )
        self.assertEqual(registry.summary()["detector_families"], [])

    def test_required_unavailable_model_still_fails(self):
        def unavailable():
            raise RuntimeError("Synthetic model unavailable")

        with patch("lsdf.scanners.gliner.build_installed_gliner_detector", unavailable):
            with self.assertRaises(DetectorUnavailableError):
                build_detector_registry(
                    ("gliner",), detector_settings={"gliner": {"required": True}}
                )

    def test_available_optional_model_keeps_other_settings(self):
        def available(*, threshold, max_chars):
            return GLiNERDetector(object(), threshold=threshold, max_chars=max_chars)

        with patch("lsdf.scanners.gliner.build_installed_gliner_detector", available):
            registry = build_detector_registry(
                ("gliner",),
                detector_settings={"gliner": {"required": False, "threshold": 0.6, "max_chars": 80}},
            )
        self.assertEqual(registry.summary()["detector_families"], ["gliner"])
        self.assertEqual(registry.detectors[0].threshold, 0.6)
        self.assertEqual(registry.detectors[0].max_chars, 80)


if __name__ == "__main__":
    unittest.main()
