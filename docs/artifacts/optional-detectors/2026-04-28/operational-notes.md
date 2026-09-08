# Optional Detector Dependency Diagnostic Artifacts

- Generated at: 2026-04-28T20:27:44.566412+00:00
- Profile: default
- Mode: enforce
- Output directory: docs/artifacts/optional-detectors/2026-04-28
- Raw-value policy: raw sensitive values are redacted; reveal mode is not used

This artifact is a dependency-unavailable diagnostic run. It demonstrates for this diagnostic run that optional detector reporting stays raw-value-safe when Presidio or OpenAI privacy-filter dependencies/model caches are absent; it is not evidence of a successful cached `broad-pii-ml` replay.

## Local Setup

Build and run optional detector diagnostics only through Docker Compose:

```bash
docker compose --profile optional build optional-test
LSDF_OPENAI_PRIVACY_FILTER_MODEL=openai/privacy-filter \
LSDF_OPENAI_PRIVACY_FILTER_LOCAL_FILES_ONLY=true \
LSDF_RUN_OPTIONAL_DETECTOR_BATTERY_SMOKE=1 \
  docker compose --profile optional run --rm optional-test
LSDF_REQUIRE_OPENAI_PRIVACY_FILTER=1 \
  docker compose --profile optional run --rm optional-test
docker compose --profile optional run --rm optional-cli optional-detector-artifacts --output-dir docs/artifacts/optional-detectors/optional-run
```

The privacy-filter path defaults to local cache only. Use the Docker-managed Hugging Face cache volume; if the model is not cached, the diagnostic artifact records a safe unavailable reason instead of downloading by default. The required smoke command needs a prepared privacy-filter cache.

## Optional Detector Status

- `presidio`: unavailable
  - Reason: Install presidio-analyzer to enable detector family 'presidio'
- `openai_privacy_filter`: unavailable
  - Reason: Install transformers and a supported model cache to enable detector family 'openai_privacy_filter'

## Reports

- safety_matrix
  - JSON: `docs/artifacts/optional-detectors/2026-04-28/safety_matrix.comparison.json`
  - Markdown: `docs/artifacts/optional-detectors/2026-04-28/safety_matrix.comparison.md`
- utility_matrix
  - JSON: `docs/artifacts/optional-detectors/2026-04-28/utility_matrix.comparison.json`
  - Markdown: `docs/artifacts/optional-detectors/2026-04-28/utility_matrix.comparison.md`
- observability_matrix
  - JSON: `docs/artifacts/optional-detectors/2026-04-28/observability_matrix.comparison.json`
  - Markdown: `docs/artifacts/optional-detectors/2026-04-28/observability_matrix.comparison.md`
