# SPDX-License-Identifier: Apache-2.0
"""Programmatic asciinema cast generator from a captured demo transcript.

Asciinema v2 cast format: a one-line JSON header followed by one
[time_seconds, "o", text] event per line. We use this to render the
deterministic golden-demo stdout (`examples/demo-media/golden-demo.captured.txt`)
into a viewer-friendly cast that can be embedded in docs via
asciinema-player.js or replayed with `asciinema play`.

Why programmatic rather than a real recording:
- The recording is reproducible from text, so re-running needs no
  interactive terminal.
- A real `asciinema rec` capture bakes in the host's prompt, terminal
  width, and any unrelated stdout — this is fine for a one-off but ages
  badly when the project's golden demo evolves.
- Operators who want a "real" recording (with their host's terminal
  styling) can still `bash scripts/record-demo.sh --with-gif`, which
  re-records via `asciinema rec` and renders to GIF via `agg`; this
  module is the deterministic baseline that ships with every checkout.

Run via:
    docker compose run --rm --entrypoint python3 cli -m lsdf.cast_recorder
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

# Tuneable timing knobs. The captured demo is short (~12 outcome lines), so
# we stretch each line out enough that a viewer can read it.
_TYPING_DELAY = 0.05  # delay applied to the leading prompt + command line
_PER_LINE_PAUSE = 0.35  # seconds between successive demo-runner output lines
_PROMPT = "$ "
_COMMAND = (
    "docker compose --profile demo up --build "
    "--abort-on-container-exit --exit-code-from demo-runner demo-runner"
)


def build_events(captured_lines: Iterable[str]) -> list[list]:
    """Convert a captured-text transcript to a list of asciinema events."""
    events: list[list] = []
    elapsed = 0.0

    # Type the prompt+command character by character so the cast feels
    # "live" rather than dumping the full command in one frame.
    prompt_text = _PROMPT + _COMMAND + "\r\n"
    for char in prompt_text:
        elapsed += _TYPING_DELAY
        events.append([round(elapsed, 4), "o", char])

    # Pause briefly after the command (simulates docker build / startup).
    elapsed += 1.5

    # Emit each captured line on its own beat. We strip the
    # `demo-runner-1  | ` compose prefix from the runner output so the cast
    # reads as the application's own narrative, but keep `Container ...`
    # status lines for context.
    for raw in captured_lines:
        line = raw.rstrip("\n").rstrip("\r")
        if not line:
            continue
        text = line + "\r\n"
        events.append([round(elapsed, 4), "o", text])
        elapsed += _PER_LINE_PAUSE

    # Trailing prompt — gives the viewer a sense the command exited cleanly.
    elapsed += 0.5
    events.append([round(elapsed, 4), "o", _PROMPT])

    return events


def write_cast(
    captured_path: Path,
    cast_path: Path,
    *,
    width: int = 100,
    height: int = 24,
    title: str = "LSDF Golden Demo",
) -> None:
    captured_lines = captured_path.read_text(encoding="utf-8").splitlines()
    events = build_events(captured_lines)
    header = {
        "version": 2,
        "width": width,
        "height": height,
        "title": title,
        "env": {"SHELL": "/bin/bash", "TERM": "xterm-256color"},
    }
    with cast_path.open("w", encoding="utf-8", newline="\n") as fh:
        fh.write(json.dumps(header, separators=(",", ":")) + "\n")
        for event in events:
            fh.write(json.dumps(event, separators=(",", ":")) + "\n")


def main() -> None:
    captured = Path("examples/demo-media/golden-demo.captured.txt")
    cast = Path("examples/demo-media/golden-demo.cast")
    if not captured.exists():
        raise SystemExit(
            f"{captured} not found — run scripts/record-demo.sh first to "
            "capture a fresh demo transcript."
        )
    write_cast(captured, cast)
    print(f"Wrote asciinema cast to {cast}")


if __name__ == "__main__":
    main()
