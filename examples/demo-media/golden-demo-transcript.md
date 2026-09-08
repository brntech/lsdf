# Golden Demo Transcript

```bash
docker compose --profile demo up --build --abort-on-container-exit --exit-code-from demo-runner demo-runner
```

Expected safe terminal close:

```text
LSDF Golden Demo: ok
- OK gateway_ready
- OK request_block
- OK response_redaction
- OK stream_redaction
- OK tool_call_block
- OK observability_sanitize
- OK health
- OK metrics
- OK audit_summary
- OK metrics_summary
```

## Captured artifacts

A real captured run from this demo command is committed in this folder:

- `golden-demo.captured.txt` — deterministic stdout transcript (the demo's own pass/fail report, with Docker build noise stripped).
- `golden-demo.cast` — asciinema v2 cast generated programmatically from `golden-demo.captured.txt` via `python -m lsdf.cast_recorder`. Replay with `asciinema play examples/demo-media/golden-demo.cast` or embed in docs via [asciinema-player](https://github.com/asciinema/asciinema-player).
- `golden-demo.gif` — *not committed*; produced on demand by `bash scripts/record-demo.sh --with-gif` (requires asciinema + agg). The host's terminal styling differs across machines so a committed GIF would age badly; the cast is the canonical replayable artifact.

To refresh the captured artifacts after a demo change:

```bash
bash scripts/record-demo.sh
```
