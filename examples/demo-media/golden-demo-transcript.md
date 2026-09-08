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

## Run and Inspect the Demo

The demo starts its own upstream and gateway and checks requests, responses, streaming, tool-call arguments, trace sanitation, health, metrics, and safe summaries. It requires no real model or provider key. Stop the demo services when finished:

```bash
docker compose --profile demo down
```

Generate a safe narration script or a proof bundle that includes the demo audit and metrics summaries:

```bash
docker compose run --rm cli demo-script --format markdown
docker compose run --rm cli proof-bundle --output .lsdf/proof --audit-jsonl-path .lsdf/demo/audit.jsonl --metrics-jsonl-path .lsdf/demo/metrics.jsonl --format markdown
```

Use actual demo output for captures and check that no raw sensitive fixture values appear before sharing a recording. The transcript and cast above are the included captured artifacts.
