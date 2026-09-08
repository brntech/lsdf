import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from lsdf.cast_recorder import build_events, write_cast


class CastRecorderTests(unittest.TestCase):
    """Programmatic asciinema cast generator from the captured demo
    transcript. The cast must be valid asciinema v2 (header JSON object on
    line 1, event arrays on subsequent lines) and must contain every line
    from the source transcript so the replay matches the committed text.
    """

    def test_build_events_emits_one_output_event_per_input_line(self):
        captured = [
            "demo-runner-1  | LSDF Golden Demo: ok",
            "demo-runner-1  | - OK gateway_ready",
            "demo-runner-1  | - OK request_block",
        ]
        events = build_events(captured)
        # Plus the typed prompt/command, the trailing prompt, and the demo
        # output lines themselves. We don't pin the prompt-typing length
        # exactly (it's a tuneable knob) — just assert each captured line
        # appears verbatim in some event.
        joined = "".join(event[2] for event in events)
        for line in captured:
            self.assertIn(
                line,
                joined,
                f"captured line missing from cast events: {line!r}",
            )

    def test_build_events_timestamps_are_monotonic_non_negative_floats(self):
        captured = [f"demo-runner-1  | line {i}" for i in range(5)]
        events = build_events(captured)
        previous = -1.0
        for event in events:
            self.assertEqual(len(event), 3, f"event must be [time, type, text]: {event}")
            self.assertIsInstance(event[0], (int, float))
            self.assertEqual(event[1], "o")
            self.assertGreaterEqual(event[0], 0.0)
            self.assertGreaterEqual(
                event[0],
                previous,
                f"timestamps must be monotonic; got {event[0]} after {previous}",
            )
            previous = event[0]

    def test_write_cast_produces_valid_asciinema_v2(self):
        with TemporaryDirectory() as tmp:
            captured_path = Path(tmp) / "captured.txt"
            cast_path = Path(tmp) / "out.cast"
            captured_path.write_text(
                "demo-runner-1  | LSDF Golden Demo: ok\n"
                "demo-runner-1  | - OK gateway_ready\n",
                encoding="utf-8",
            )
            write_cast(captured_path, cast_path, width=120, height=30, title="t")

            lines = cast_path.read_text(encoding="utf-8").splitlines()
            self.assertGreater(len(lines), 1, "cast must have header + events")
            header = json.loads(lines[0])
            self.assertEqual(header["version"], 2)
            self.assertEqual(header["width"], 120)
            self.assertEqual(header["height"], 30)
            self.assertEqual(header["title"], "t")
            for raw in lines[1:]:
                event = json.loads(raw)
                self.assertEqual(len(event), 3)
                self.assertEqual(event[1], "o")

    def test_committed_cast_matches_committed_captured_text(self):
        """The committed cast file must reflect the committed captured text.
        If a future change refreshes captured.txt without re-running the cast
        generator, the cast becomes stale — this test makes that loud.
        """
        captured = Path("examples/demo-media/golden-demo.captured.txt")
        cast = Path("examples/demo-media/golden-demo.cast")
        if not captured.exists() or not cast.exists():
            self.skipTest("demo-media artifacts not generated")
        with TemporaryDirectory() as tmp:
            fresh = Path(tmp) / "fresh.cast"
            write_cast(captured, fresh)
            self.assertEqual(
                fresh.read_text(encoding="utf-8"),
                cast.read_text(encoding="utf-8"),
                "Committed golden-demo.cast is out of sync with "
                "golden-demo.captured.txt — re-run "
                "`docker compose run --rm --entrypoint python3 cli "
                "-m lsdf.cast_recorder` (or `bash scripts/record-demo.sh`) "
                "to regenerate.",
            )


if __name__ == "__main__":
    unittest.main()
