# Comparative Protection

This recorded artifact compares LSDF detector stacks against a public PII comparator on the same corpus selection used in that run. Four threat corpora remain bundled. The ai4privacy sample is no longer distributed; its labeled rows are historical external benchmark evidence, not a fresh four-corpus comparison. It is detector-normalized: every stack uses the same LSDF `broad-pii` policy/action layer, so differences below are about what each detector family finds, not about different redaction engines.

## Comparator Survey

| Option | Why it mattered | Decision |
| --- | --- | --- |
| Microsoft Presidio | OSS PII detection/de-identification SDK with analyzer, anonymizer, recognizers, NLP, pattern matching, checksums, and MIT licensing. | Measured comparator. It is the closest reproducible OSS alternative to LSDF's PII detector layer. |
| Regex-only baseline | Represents the common naive detector a local agent developer can assemble quickly. | Measured baseline so LSDF's incremental value over simple patterns is visible. |
| NVIDIA NeMo Guardrails | Framework with sensitive-data rails, including Presidio and GLiNER-backed flows. | Not separately measured because its PII path composes the same detector families already compared here. |
| Llama Guard / Granite Guardian | Broad safety classifiers for prompts/responses and risk categories; useful guardrails, but not span-level PII anonymizers. | Surveyed only; not a fair shared-corpus PII redaction comparator without a custom policy harness. |
| Lakera Guard / Cloudflare AI Security for Apps | Managed guardrail services with PII/data-leakage features. | Surveyed only; API-key service behavior is not locally reproducible from the public repo. |

Sources surveyed: [Microsoft Presidio](https://microsoft.github.io/presidio/), [NVIDIA NeMo Guardrails PII detection](https://docs.nvidia.com/nemo/guardrails/latest/configure-rails/guardrail-catalog/index.html), [Meta Llama Guard 3](https://huggingface.co/meta-llama/Llama-Guard-3-1B), [IBM Granite Guardian](https://www.ibm.com/us-en/granite/docs/models/guardian), [Lakera Guard](https://docs.lakera.ai/guard), and [Cloudflare PII detection](https://developers.cloudflare.com/waf/detections/ai-security-for-apps/pii-detection/).

## Method

- Policy/action layer: `broad-pii`.
- Bundled threat corpora: `evals/piece_b_replay.json`, `evals/medical_phi_replay.json`, `evals/nemotron_pii.json`, `evals/br_agentic_pii.json`.
- Historical external benchmark: `ai4privacy_multilingual`, no longer bundled. Its recorded comparison rows are retained below; an operator-supplied local dataset requires appropriate upstream permissions.
- Benign corpora: `evals/false_positive.json`, `evals/utility_matrix.json`.
- Metrics: value-level recall on threat corpora; specificity is 1 minus the benign case failure rate.
- Raw-value safety: the generated report contains counts only, not sensitive fixture values.
- Reproducibility: optional detector RNGs are seeded with `0` before the run. GLiNER/PyTorch CPU inference can still move threshold-edge spans by a few values between independent artifact generations; compare detector stacks within this artifact, and use `EVAL.md` as the release-gate source of truth.

## Threat Corpus Results

| Stack | Corpus | Cases | Values before | Values after | Recall | After-leak cases | Blocked |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `regex_only` | `piece_b_replay` | 40 | 36 | 2 | 0.944 | 2 | 30 |
| `regex_only` | `medical_phi_replay` | 30 | 54 | 53 | 0.019 | 30 | 0 |
| `regex_only` | `nemotron_pii` | 100 | 663 | 525 | 0.208 | 99 | 4 |
| `regex_only` | `ai4privacy_multilingual` (historical external benchmark) | 134 | 949 | 732 | 0.229 | 131 | 4 |
| `regex_only` | `br_agentic_pii` | 8 | 39 | 6 | 0.846 | 5 | 8 |
| `presidio` | `piece_b_replay` | 40 | 36 | 29 | 0.194 | 29 | 0 |
| `presidio` | `medical_phi_replay` | 30 | 54 | 51 | 0.056 | 30 | 0 |
| `presidio` | `nemotron_pii` | 100 | 663 | 447 | 0.326 | 99 | 0 |
| `presidio` | `ai4privacy_multilingual` (historical external benchmark) | 134 | 949 | 756 | 0.203 | 130 | 0 |
| `presidio` | `br_agentic_pii` | 8 | 39 | 10 | 0.744 | 7 | 0 |
| `lsdf_dependency_light` | `piece_b_replay` | 40 | 36 | 0 | 1.000 | 0 | 32 |
| `lsdf_dependency_light` | `medical_phi_replay` | 30 | 54 | 21 | 0.611 | 12 | 0 |
| `lsdf_dependency_light` | `nemotron_pii` | 100 | 663 | 486 | 0.267 | 97 | 30 |
| `lsdf_dependency_light` | `ai4privacy_multilingual` (historical external benchmark) | 134 | 949 | 640 | 0.326 | 128 | 56 |
| `lsdf_dependency_light` | `br_agentic_pii` | 8 | 39 | 6 | 0.846 | 5 | 8 |
| `lsdf_broad_pii` | `piece_b_replay` | 40 | 36 | 0 | 1.000 | 0 | 32 |
| `lsdf_broad_pii` | `medical_phi_replay` | 30 | 54 | 3 | 0.944 | 2 | 0 |
| `lsdf_broad_pii` | `nemotron_pii` | 100 | 663 | 209 | 0.685 | 79 | 24 |
| `lsdf_broad_pii` | `ai4privacy_multilingual` (historical external benchmark) | 134 | 949 | 276 | 0.709 | 85 | 37 |
| `lsdf_broad_pii` | `br_agentic_pii` | 8 | 39 | 1 | 0.974 | 1 | 8 |

## Benign Specificity

| Stack | Corpus | Cases | Passed | Failed | Specificity | Findings by family |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| `regex_only` | `false_positive` | 4 | 4 | 0 | 1.000 | _none_ |
| `regex_only` | `utility_matrix` | 65 | 65 | 0 | 1.000 | _none_ |
| `presidio` | `false_positive` | 4 | 4 | 0 | 1.000 | _none_ |
| `presidio` | `utility_matrix` | 65 | 61 | 4 | 0.938 | presidio=4 |
| `lsdf_dependency_light` | `false_positive` | 4 | 4 | 0 | 1.000 | _none_ |
| `lsdf_dependency_light` | `utility_matrix` | 65 | 65 | 0 | 1.000 | medical-regex=2 |
| `lsdf_broad_pii` | `false_positive` | 4 | 4 | 0 | 1.000 | _none_ |
| `lsdf_broad_pii` | `utility_matrix` | 65 | 65 | 0 | 1.000 | gliner=1, medical-regex=2 |

## Honest Read

- `lsdf_broad_pii` is the release-gated local LSDF stack in this comparison. It is the fair LSDF-vs-Presidio read for broad PII/PHI coverage.
- In the recorded comparison, `lsdf_broad_pii` had higher threat recall than `regex_only` and `presidio` on each evaluated corpus, including the historical external benchmark. This is evidence from that run, not a guarantee on new data.
- `lsdf_dependency_light` is fast and local-agent friendly, but the broad external PII corpora show where it is not the right competitor: use `broad-pii` or `broad-pii-ml` when value-level broad PII recall is the goal.
- Dependency-light LSDF ties `regex_only` on `br_agentic_pii` at 0.846; extra entropy/medical detectors add no value for that corpus.
- Dependency-light LSDF loses to `presidio` on `nemotron_pii`: 0.267 vs 0.326.
- Presidio also produced benign false positives in this run, so using it as a drop-in default would require threshold or recognizer tuning before enforcement.
- Presidio remains the strongest public OSS comparator for standalone PII detection. LSDF's differentiator is cross-surface OpenAI-compatible enforcement: messages, RAG, tool results, tool-call arguments, reasoning, traces, and logs share one policy/action layer.

## Reproduce

Run from the repository root with the optional detector image available. This command regenerates the comparison over the current four bundled corpora; it does not reproduce the historical external ai4privacy rows:

```bash
docker compose --profile optional run --rm --entrypoint python optional-cli \
  scripts/build_comparative_protection.py \
  --output docs/comparative-protection.md \
  --seed 0
```

For a single-corpus direct comparison table, use the existing CLI:

```bash
docker compose --profile optional run --rm optional-cli compare-detectors \
  evals/br_agentic_pii.json \
  --profile broad-pii \
  --set regex_only=regex \
  --set presidio=presidio \
  --set lsdf_dependency_light=regex,entropy,medical-regex,contextual-anchored \
  --set lsdf_broad_pii=regex,entropy,medical-regex,contextual-anchored,contextual-broad,gliner \
  --format markdown
```

To compare against an external ai4privacy file you are permitted to use, pass `.lsdf/external-benchmarks/ai4privacy_multilingual.json` in place of the positional `evals/br_agentic_pii.json` path in the last command and keep the output local. See [Measured Protection](measured-protection.md#operator-supplied-external-benchmark) for a full four-plus-external release evaluation and healthcare's unchanged missing-corpus gate behavior. LSDF-authored comparator adapters are Apache-2.0; optional upstream packages and model weights retain their own licenses, as described in [Third-Party Notices](../THIRD_PARTY_NOTICES.md).
