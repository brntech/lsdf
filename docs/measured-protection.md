# Measured Protection

Evidence recorded: 2026-05-06 to 2026-05-07. Distribution and reproduction guidance updated: 2026-09-08.

LSDF separates dependency-light defaults from release-gated broad-pii detection. The default gateway uses regex, entropy, and lightweight medical-pattern detectors. `balanced` keeps that dependency-light base and adds generic output redaction. `broad-pii` adds contextual-broad and GLiNER adapters for span-scope PII/PHI redaction. `broad-pii-ml` uses the same local broad-pii stack and loads OpenAI privacy-filter when the reference model is available; the optional Docker image isolates the GLiNER and privacy-filter Python dependency stacks so both can run in the same profile.

The current release gate in `EVAL.md` follows each profile's stated containment posture. `broad-pii` and `broad-pii-ml` must hold value-level recall >= 0.90 on piece_b_replay, medical_phi_replay, and BR-Agentic-PII, with benign specificity >= 0.95. Nemotron-PII is bundled characterization evidence for those broad tiers; ai4privacy multilingual metrics are historical external benchmark evidence. Healthcare retains both in its surface-containment promise, so a healthcare evaluation fails the gate when the required external ai4privacy corpus is missing.

## Public Reproducible Artifacts

The default evaluation suite bundles four threat corpora (`evals/piece_b_replay.json`, `evals/medical_phi_replay.json`, `evals/nemotron_pii.json`, `evals/br_agentic_pii.json`) and two benign corpora (`evals/false_positive.json`, `evals/utility_matrix.json`). The generated reports contain aggregate measurements without raw fixture values. The committed EVAL and comparison tables retain their recorded results; ai4privacy rows and aggregates that include them are labeled historical external benchmark evidence.

- **`EVAL.md`** - per-release signal-vs-noise snapshot. Per-profile threat-corpus containment, per-detector-family threat findings vs benign findings, per-profile p50/p95 on a representative payload. Regenerate with `docker compose run --rm cli eval-report --profile default --profile balanced --format markdown > EVAL.md` (dependency-light profiles) or `docker compose --profile optional run --rm optional-cli eval-report --profile default --profile balanced --profile broad-pii --profile broad-pii-ml --format markdown > EVAL.md` (with the optional ML adapter).
- **`docs/performance.md`** - per-profile, per-payload latency table (small chat / medium with RAG / large assistant reply / RAG-heavy session). p50/p95/p99 plus throughput. Regenerate via `cli latency-table` with the same profile flags as above.

Headline numbers from the recorded regeneration are committed alongside both files; they are not a new run after removing the external fixture. Threat-corpus replay containment (40 sanitized credential-leak cases): `default` profile redacts to 2 sensitive values remaining (PII log-only); `broad-pii-ml` profile reaches 0 sensitive values remaining.

## Optional ML Characterization Status

Reproduce the `broad-pii-ml` profile's containment on your machine:

```bash
docker compose --profile optional run --rm optional-cli eval evals/piece_b_replay.json --profile broad-pii-ml --format markdown
```

The 6-case ML-only PII follow-up corpus runs identically against `evals/piece_b_replay_ml_pii.json`. The default threat suite adds `evals/medical_phi_replay.json`, `evals/nemotron_pii.json`, and `evals/br_agentic_pii.json` to the credential replay. For `broad-pii` and `broad-pii-ml`, the gate covers their three span-scope promise corpora; Nemotron-PII is additional characterization. The former ai4privacy sample is not committed or distributed. Its historical metrics require the separately supplied external benchmark described below.

The public corpora and reproducible artifacts above provide the recorded evaluation evidence. The OpenAI privacy-filter family is optional: `broad-pii-ml` uses it when loadable and skips it when the reference model is unavailable, rather than making the whole profile unusable. Treat the release gate as scoped measured evidence, not public proof of universal detection.

After the score-threshold tune (factory default raised from `0.50` to `0.85` via the measurement-first sweep at `docs/fp-lever-sweep-2026-04-29.md`), the optional ML profile produces about 3 `openai_privacy_filter` benign findings on `evals/utility_matrix.json`, down from 27 on the same corpus at the prior `0.50` default. Operators routing real PII through the optional profile should monitor `LSDF_OPENAI_PRIVACY_FILTER_SCORE_THRESHOLD` (env-overridable, validated to `[0.0, 1.0]`) and lower it if their traffic mix surfaces recall regressions on harder PII shapes than the bundled follow-up corpus exercises. Public-figure PERSON findings are already deny-listed at the registry level and extensible via `LSDF_PERSON_DENY_LIST_EXTRA`.

## Operator-Supplied External Benchmark

LSDF no longer bundles the sample derived from [ai4privacy/pii-masking-300k](https://huggingface.co/datasets/ai4privacy/pii-masking-300k). Obtain the appropriate upstream dataset permissions before preparing or using a local copy. Keep it under ignored `.lsdf/external-benchmarks/`, outside Git, Docker image build contents, and release archives. The old reported license is historical metadata; consult the upstream dataset's current terms for the version and use you select.

Prepare the external file in LSDF evaluation format with its corpus `name` set to `ai4privacy_multilingual`. Each explicit `--threat-dataset` list replaces the defaults, so include all four bundled paths together with the local file:

```bash
docker compose --profile optional run --rm optional-cli eval-report \
  --profile broad-pii --profile broad-pii-ml --profile healthcare \
  --threat-dataset evals/piece_b_replay.json \
  --threat-dataset evals/medical_phi_replay.json \
  --threat-dataset evals/nemotron_pii.json \
  --threat-dataset evals/br_agentic_pii.json \
  --threat-dataset .lsdf/external-benchmarks/ai4privacy_multilingual.json \
  --format markdown > .lsdf/external-benchmarks/eval-report.md
```

Healthcare's existing five-corpus `gate_promise` remains unchanged. Omitting its external corpus fails the gate for missing evidence. Supplying it enables evaluation of that promise; all recall and specificity floors must still pass. Historical external benchmark numbers also depend on the recorded sample, policies, detector versions, and models and are not reproduced by a fresh bundled-only run.

## Multilingual PII Probes

The optional ML path was also probed on Arabic, Chinese, and Spanish PII examples. The reference adapter detected names, phone numbers, addresses, emails, date/account-number-like identifiers, or comparable private-person fields in those probes.

These probes show useful multilingual behavior, but they are not a full multilingual benchmark. Teams should add their own language, locale, and domain fixtures before relying on automated enforcement.

## False-Positive Evidence

The optional ML plus entropy combination stayed clean on a small benign smoke set of technical prose and placeholder/code-like text. That is encouraging, but the sample is too small to claim a broad false-positive rate.

For production pilots, run `monitor` or `broad-pii-ml` against a representative traffic sample, review audit summaries, then move selected surfaces to enforcement.

## Optional Code, Packages, and Model Weights

The core and every LSDF-authored adapter remain Apache-2.0 source in this repository. GLiNER, Presidio, and OpenAI privacy-filter integrations are optional. Their upstream Python packages and downloaded model weights retain their own licenses and notices; LSDF's license does not replace those terms. The exact reference model cards and upstream projects are linked in [Third-Party Notices](../THIRD_PARTY_NOTICES.md). Optional runtime setup is separate from dataset permission for an external benchmark.

## How To Run The Optional Path

```bash
docker compose --profile optional build gateway-ml
docker compose run --rm cli policy-validate --profile broad-pii-ml
docker compose --profile optional run --rm optional-cli doctor --profile broad-pii-ml
LSDF_UPSTREAM_BASE_URL=http://host.docker.internal:8000 \
  docker compose --profile optional up gateway-ml
```

`gateway-ml` and `gateway` both bind `localhost:8080` by default. Run one at a time or remap host ports.

The privacy-filter adapter defaults to local-files-only model loading. If the model is not present or cannot be loaded from the Docker-managed cache, `broad-pii-ml` continues with the local broad-pii stack. In the bundled optional image, OpenAI privacy-filter runs through an isolated worker venv with Transformers 5.7, while GLiNER remains on its compatible Transformers 4.51 runtime. Set `LSDF_OPENAI_PRIVACY_FILTER_LOCAL_FILES_ONLY=false` only when you intentionally want the optional service to try populating the model cache. The optional ML profile also scans streaming output through the same rolling holdback path as dependency-light detectors, so validate latency on representative streams before enforcing high-volume traffic.

For release validation with a prepared cache, require the real privacy-filter smoke path:

```bash
LSDF_REQUIRE_OPENAI_PRIVACY_FILTER=1 \
  docker compose --profile optional run --rm optional-test
```

## Healthcare Limits

The built-in `medical-regex` detector is a lightweight pattern scanner. It catches selected diagnosis text, ICD-like codes, lab-value strings, and medication-dosage patterns. It is not full HIPAA de-identification and does not replace medical NER, clinical review, or compliance validation.
