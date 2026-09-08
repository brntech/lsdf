# LSDF Eval Report

_Generated 2026-05-07T05:09:39Z._

Recorded signal-vs-noise snapshot for the dependency-light defaults and the optional ML-enhanced profile.

**Benchmark availability:** the numeric results below retain their generated date above. The current distribution bundles four threat corpora: `piece_b_replay`, `medical_phi_replay`, `nemotron_pii`, and `br_agentic_pii`. The ai4privacy sample is no longer bundled; its rows and the cross-corpus aggregates that include it are historical external benchmark evidence, not a fresh four-corpus run. An operator may supply an appropriately licensed local copy under ignored `.lsdf/external-benchmarks/`; see the reproduction instructions below.

## Release Gate

Release-gated profiles must hold the value-level recall floor declared in their YAML `gate_promise:` block on every promised threat corpus, plus the promised benign specificity floor.

`broad-pii` and `broad-pii-ml` promise span-scope redaction on `piece_b_replay`, `medical_phi_replay`, and `br_agentic_pii`; Nemotron-PII and the historical external ai4privacy benchmark characterize those profiles without adding a release floor. `healthcare` retains its five-corpus surface-containment promise, including `ai4privacy_multilingual`. A healthcare evaluation using only the four bundled corpora fails the gate for the missing promised dataset. Supplying the external corpus restores the required input; it does not guarantee that the recall and specificity floors pass. Healthcare containment is not a compliance certification. The PASS rows below belong to the recorded run and its listed profiles.

| Profile | Status | Detail |
| --- | --- | --- |
| broad-pii | PASS | all floors held |
| broad-pii-ml | PASS | all floors held |

## Corpora

| Corpus | Path | Cases | Role | Source |
| --- | --- | ---: | --- | --- |
| piece_b_replay | `evals/piece_b_replay.json` | 40 | threat | _internal_ |
| medical_phi_replay | `evals/medical_phi_replay.json` | 30 | threat | _internal_ |
| nemotron_pii | `evals/nemotron_pii.json` | 100 | threat | `nvidia/Nemotron-PII` (CC-BY-4.0) |
| ai4privacy_multilingual | Not bundled; operator-supplied local file | 134 (historical) | historical external benchmark | [ai4privacy/pii-masking-300k](https://huggingface.co/datasets/ai4privacy/pii-masking-300k) (recorded source license: CC-BY-NC-4.0; consult upstream terms) |
| br_agentic_pii | `evals/br_agentic_pii.json` | 8 | threat | `guardion/BR-Agentic-PII-Benchmark` (MIT) |
| false_positive.json | `evals/false_positive.json` | 4 | benign | _internal_ |
| utility_matrix | `evals/utility_matrix.json` | 65 | benign | _internal_ |

## External Corpus Selection

- `br_agentic_pii`: Surveyed PIIBench, HiveTrace PII-Bench (ru), ai4privacy PHI, and BR-Agentic-PII-Benchmark. BR-Agentic was selected because it is small, MIT-licensed, fully synthetic, Portuguese, and explicitly models agent tool arguments/results; PIIBench overlaps existing ai4privacy/Nemotron sources and carries constituent-license complexity, while HiveTrace is access-gated/evaluation-only and ai4privacy PHI overlaps the existing medical_phi_replay focus.

## Threat-corpus containment

Rows marked historical external benchmark are retained counts from the earlier ai4privacy run; its fixture is not distributed.

| Profile | Corpus | Cases | Blocked | Sensitive values before | Sensitive values after | Cases with leak after |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| default | piece_b_replay | 40 | 6 | 36 | 2 | 2 |
| default | medical_phi_replay | 30 | 0 | 54 | 22 | 12 |
| default | nemotron_pii | 100 | 0 | 663 | 612 | 99 |
| default | ai4privacy_multilingual (historical external benchmark) | 134 | 0 | 949 | 828 | 131 |
| default | br_agentic_pii | 8 | 8 | 39 | 31 | 8 |
| balanced | piece_b_replay | 40 | 6 | 36 | 0 | 0 |
| balanced | medical_phi_replay | 30 | 0 | 54 | 21 | 12 |
| balanced | nemotron_pii | 100 | 0 | 663 | 486 | 97 |
| balanced | ai4privacy_multilingual (historical external benchmark) | 134 | 0 | 949 | 640 | 128 |
| balanced | br_agentic_pii | 8 | 8 | 39 | 31 | 8 |
| broad-pii | piece_b_replay | 40 | 32 | 36 | 0 | 0 |
| broad-pii | medical_phi_replay | 30 | 0 | 54 | 3 | 2 |
| broad-pii | nemotron_pii | 100 | 24 | 663 | 212 | 79 |
| broad-pii | ai4privacy_multilingual (historical external benchmark) | 134 | 37 | 949 | 280 | 87 |
| broad-pii | br_agentic_pii | 8 | 8 | 39 | 1 | 1 |
| broad-pii-ml | piece_b_replay | 40 | 32 | 36 | 0 | 0 |
| broad-pii-ml | medical_phi_replay | 30 | 0 | 54 | 1 | 1 |
| broad-pii-ml | nemotron_pii | 100 | 21 | 663 | 190 | 77 |
| broad-pii-ml | ai4privacy_multilingual (historical external benchmark) | 134 | 45 | 949 | 116 | 57 |
| broad-pii-ml | br_agentic_pii | 8 | 8 | 39 | 0 | 0 |

## Detection metrics (presidio-research β=2 convention; value-level recall, specificity in place of precision)

Per-corpus value-level recall, benign specificity (1 minus the FP case rate across benign corpora), and recall-weighted F2. Recall = (sensitive values present pre-inspection − sensitive values present post-inspection) ÷ pre-inspection. Specificity treats every benign case that produced one or more findings as a false positive. F2 follows Microsoft presidio-research's default β=2 — recall is weighted more heavily than precision because LSDF's threat model treats a missed leak as strictly worse than a benign FP.

| Profile | Corpus | Recall | Specificity | F2 |
| --- | --- | ---: | ---: | ---: |
| default | piece_b_replay | 0.944 | 1.000 | 0.955 |
| default | medical_phi_replay | 0.593 | 1.000 | 0.645 |
| default | nemotron_pii | 0.077 | 1.000 | 0.094 |
| default | ai4privacy_multilingual (historical external benchmark) | 0.128 | 1.000 | 0.154 |
| default | br_agentic_pii | 0.205 | 1.000 | 0.244 |
| balanced | piece_b_replay | 1.000 | 1.000 | 1.000 |
| balanced | medical_phi_replay | 0.611 | 1.000 | 0.663 |
| balanced | nemotron_pii | 0.267 | 1.000 | 0.313 |
| balanced | ai4privacy_multilingual (historical external benchmark) | 0.326 | 1.000 | 0.376 |
| balanced | br_agentic_pii | 0.205 | 1.000 | 0.244 |
| broad-pii | piece_b_replay | 1.000 | 1.000 | 1.000 |
| broad-pii | medical_phi_replay | 0.944 | 1.000 | 0.955 |
| broad-pii | nemotron_pii | 0.680 | 1.000 | 0.727 |
| broad-pii | ai4privacy_multilingual (historical external benchmark) | 0.705 | 1.000 | 0.749 |
| broad-pii | br_agentic_pii | 0.974 | 1.000 | 0.979 |
| broad-pii-ml | piece_b_replay | 1.000 | 1.000 | 1.000 |
| broad-pii-ml | medical_phi_replay | 0.981 | 1.000 | 0.985 |
| broad-pii-ml | nemotron_pii | 0.713 | 1.000 | 0.757 |
| broad-pii-ml | ai4privacy_multilingual (historical external benchmark) | 0.878 | 1.000 | 0.900 |
| broad-pii-ml | br_agentic_pii | 1.000 | 1.000 | 1.000 |

## Per-entity-type containment and exact-tag recall (LSDF canonical vocabulary)

Historical case-level metrics per entity type, aggregated across the five corpora in the recorded run, including the external ai4privacy benchmark. "Expected" counts cases whose annotation lists that entity in `expected_entities`. "Contained" credits the case when LSDF blocked it or when every annotated sensitive value that was present before inspection is absent after inspection. "Exact-tag" counts cases where `Firewall.evaluate` produced at least one finding whose LSDF entity exactly matched the annotation. Exact tags measure attribution, not leak prevention: broad PHI, contextual, or whole-surface policies can contain MRN, bank-account, DOB, or other values under a broader finding without preserving the narrow original label. Because the evaluated corpora annotate values rather than offsets or entity-to-value links, containment is a conservative full-case proxy.

### default

| Entity | Expected cases | Contained cases | Containment recall | Exact-tag cases | Exact-tag recall |
| --- | ---: | ---: | ---: | ---: | ---: |
| ADDRESS | 99 | 9 | 0.091 | 30 | 0.303 |
| PERSON | 97 | 8 | 0.082 | 49 | 0.505 |
| EMAIL | 68 | 7 | 0.103 | 68 | 1.000 |
| PHONE | 63 | 8 | 0.127 | 42 | 0.667 |
| DATE_OF_BIRTH | 40 | 0 | 0.000 | 17 | 0.425 |
| OTHER_STRONG_ID | 31 | 1 | 0.032 | 18 | 0.581 |
| API_KEY | 23 | 19 | 0.826 | 18 | 0.783 |
| BANK_ACCOUNT | 14 | 0 | 0.000 | 4 | 0.286 |
| OTHER_SECRET | 13 | 3 | 0.231 | 10 | 0.769 |
| PASSWORD | 11 | 0 | 0.000 | 2 | 0.182 |
| MEDICATION | 10 | 4 | 0.400 | 7 | 0.700 |
| BR_CPF | 8 | 8 | 1.000 | 8 | 1.000 |
| OTHER_PHI | 8 | 2 | 0.250 | 0 | 0.000 |
| MEDICAL_CONDITION | 7 | 3 | 0.429 | 3 | 0.429 |
| CREDIT_CARD | 6 | 1 | 0.167 | 1 | 0.167 |
| ICD_CODE | 6 | 6 | 1.000 | 6 | 1.000 |
| AWS_KEY | 5 | 5 | 1.000 | 4 | 0.800 |
| DIAGNOSIS_TEXT | 5 | 4 | 0.800 | 5 | 1.000 |
| LAB_VALUE | 5 | 5 | 1.000 | 5 | 1.000 |
| US_SSN | 5 | 1 | 0.200 | 5 | 1.000 |
| MRN | 4 | 1 | 0.250 | 1 | 0.250 |
| HEALTH_INSURANCE_ID | 3 | 0 | 0.000 | 0 | 0.000 |
| JWT | 2 | 2 | 1.000 | 1 | 0.500 |
| PEM_BLOCK | 2 | 1 | 0.500 | 2 | 1.000 |
| AZURE_KEY | 1 | 1 | 1.000 | 1 | 1.000 |
| BEARER_TOKEN | 1 | 1 | 1.000 | 1 | 1.000 |
| BLOOD_TYPE | 1 | 0 | 0.000 | 0 | 0.000 |
| DATABASE_URL | 1 | 1 | 1.000 | 1 | 1.000 |
| IBAN | 1 | 1 | 1.000 | 1 | 1.000 |

### balanced

| Entity | Expected cases | Contained cases | Containment recall | Exact-tag cases | Exact-tag recall |
| --- | ---: | ---: | ---: | ---: | ---: |
| ADDRESS | 99 | 11 | 0.111 | 30 | 0.303 |
| PERSON | 97 | 10 | 0.103 | 49 | 0.505 |
| EMAIL | 68 | 11 | 0.162 | 68 | 1.000 |
| PHONE | 63 | 10 | 0.159 | 42 | 0.667 |
| DATE_OF_BIRTH | 40 | 3 | 0.075 | 17 | 0.425 |
| OTHER_STRONG_ID | 31 | 2 | 0.065 | 18 | 0.581 |
| API_KEY | 23 | 19 | 0.826 | 18 | 0.783 |
| BANK_ACCOUNT | 14 | 0 | 0.000 | 4 | 0.286 |
| OTHER_SECRET | 13 | 3 | 0.231 | 10 | 0.769 |
| PASSWORD | 11 | 0 | 0.000 | 2 | 0.182 |
| MEDICATION | 10 | 4 | 0.400 | 7 | 0.700 |
| BR_CPF | 8 | 8 | 1.000 | 8 | 1.000 |
| OTHER_PHI | 8 | 2 | 0.250 | 0 | 0.000 |
| MEDICAL_CONDITION | 7 | 3 | 0.429 | 3 | 0.429 |
| CREDIT_CARD | 6 | 1 | 0.167 | 1 | 0.167 |
| ICD_CODE | 6 | 6 | 1.000 | 6 | 1.000 |
| AWS_KEY | 5 | 5 | 1.000 | 4 | 0.800 |
| DIAGNOSIS_TEXT | 5 | 4 | 0.800 | 5 | 1.000 |
| LAB_VALUE | 5 | 5 | 1.000 | 5 | 1.000 |
| US_SSN | 5 | 2 | 0.400 | 5 | 1.000 |
| MRN | 4 | 1 | 0.250 | 1 | 0.250 |
| HEALTH_INSURANCE_ID | 3 | 0 | 0.000 | 0 | 0.000 |
| JWT | 2 | 2 | 1.000 | 1 | 0.500 |
| PEM_BLOCK | 2 | 1 | 0.500 | 2 | 1.000 |
| AZURE_KEY | 1 | 1 | 1.000 | 1 | 1.000 |
| BEARER_TOKEN | 1 | 1 | 1.000 | 1 | 1.000 |
| BLOOD_TYPE | 1 | 0 | 0.000 | 0 | 0.000 |
| DATABASE_URL | 1 | 1 | 1.000 | 1 | 1.000 |
| IBAN | 1 | 1 | 1.000 | 1 | 1.000 |

### broad-pii

| Entity | Expected cases | Contained cases | Containment recall | Exact-tag cases | Exact-tag recall |
| --- | ---: | ---: | ---: | ---: | ---: |
| ADDRESS | 99 | 47 | 0.475 | 84 | 0.848 |
| PERSON | 97 | 44 | 0.454 | 83 | 0.856 |
| EMAIL | 68 | 33 | 0.485 | 68 | 1.000 |
| PHONE | 63 | 32 | 0.508 | 57 | 0.905 |
| DATE_OF_BIRTH | 40 | 22 | 0.550 | 39 | 0.975 |
| OTHER_STRONG_ID | 31 | 15 | 0.484 | 21 | 0.677 |
| API_KEY | 23 | 23 | 1.000 | 18 | 0.783 |
| BANK_ACCOUNT | 14 | 4 | 0.286 | 6 | 0.429 |
| OTHER_SECRET | 13 | 10 | 0.769 | 10 | 0.769 |
| PASSWORD | 11 | 10 | 0.909 | 2 | 0.182 |
| MEDICATION | 10 | 10 | 1.000 | 10 | 1.000 |
| BR_CPF | 8 | 8 | 1.000 | 8 | 1.000 |
| OTHER_PHI | 8 | 5 | 0.625 | 0 | 0.000 |
| MEDICAL_CONDITION | 7 | 6 | 0.857 | 7 | 1.000 |
| CREDIT_CARD | 6 | 3 | 0.500 | 6 | 1.000 |
| ICD_CODE | 6 | 6 | 1.000 | 6 | 1.000 |
| AWS_KEY | 5 | 5 | 1.000 | 4 | 0.800 |
| DIAGNOSIS_TEXT | 5 | 5 | 1.000 | 1 | 0.200 |
| LAB_VALUE | 5 | 5 | 1.000 | 1 | 0.200 |
| US_SSN | 5 | 2 | 0.400 | 5 | 1.000 |
| MRN | 4 | 2 | 0.500 | 4 | 1.000 |
| HEALTH_INSURANCE_ID | 3 | 0 | 0.000 | 1 | 0.333 |
| JWT | 2 | 2 | 1.000 | 1 | 0.500 |
| PEM_BLOCK | 2 | 2 | 1.000 | 2 | 1.000 |
| AZURE_KEY | 1 | 1 | 1.000 | 1 | 1.000 |
| BEARER_TOKEN | 1 | 1 | 1.000 | 1 | 1.000 |
| BLOOD_TYPE | 1 | 0 | 0.000 | 1 | 1.000 |
| DATABASE_URL | 1 | 1 | 1.000 | 1 | 1.000 |
| IBAN | 1 | 1 | 1.000 | 1 | 1.000 |

### broad-pii-ml

| Entity | Expected cases | Contained cases | Containment recall | Exact-tag cases | Exact-tag recall |
| --- | ---: | ---: | ---: | ---: | ---: |
| ADDRESS | 99 | 55 | 0.556 | 93 | 0.939 |
| PERSON | 97 | 58 | 0.598 | 95 | 0.979 |
| EMAIL | 68 | 37 | 0.544 | 68 | 1.000 |
| PHONE | 63 | 36 | 0.571 | 58 | 0.921 |
| DATE_OF_BIRTH | 40 | 26 | 0.650 | 40 | 1.000 |
| OTHER_STRONG_ID | 31 | 22 | 0.710 | 18 | 0.581 |
| API_KEY | 23 | 23 | 1.000 | 18 | 0.783 |
| BANK_ACCOUNT | 14 | 3 | 0.214 | 10 | 0.714 |
| OTHER_SECRET | 13 | 8 | 0.615 | 8 | 0.615 |
| PASSWORD | 11 | 10 | 0.909 | 2 | 0.182 |
| MEDICATION | 10 | 10 | 1.000 | 10 | 1.000 |
| BR_CPF | 8 | 8 | 1.000 | 8 | 1.000 |
| OTHER_PHI | 8 | 6 | 0.750 | 0 | 0.000 |
| MEDICAL_CONDITION | 7 | 6 | 0.857 | 7 | 1.000 |
| CREDIT_CARD | 6 | 3 | 0.500 | 6 | 1.000 |
| ICD_CODE | 6 | 6 | 1.000 | 6 | 1.000 |
| AWS_KEY | 5 | 5 | 1.000 | 4 | 0.800 |
| DIAGNOSIS_TEXT | 5 | 5 | 1.000 | 1 | 0.200 |
| LAB_VALUE | 5 | 5 | 1.000 | 1 | 0.200 |
| US_SSN | 5 | 2 | 0.400 | 5 | 1.000 |
| MRN | 4 | 2 | 0.500 | 4 | 1.000 |
| HEALTH_INSURANCE_ID | 3 | 0 | 0.000 | 1 | 0.333 |
| JWT | 2 | 2 | 1.000 | 1 | 0.500 |
| PEM_BLOCK | 2 | 2 | 1.000 | 2 | 1.000 |
| AZURE_KEY | 1 | 1 | 1.000 | 1 | 1.000 |
| BEARER_TOKEN | 1 | 1 | 1.000 | 1 | 1.000 |
| BLOOD_TYPE | 1 | 0 | 0.000 | 1 | 1.000 |
| DATABASE_URL | 1 | 1 | 1.000 | 1 | 1.000 |
| IBAN | 1 | 1 | 1.000 | 1 | 1.000 |

## Benign-corpus findings (lower is better)

Findings on benign cases are FP candidates. `expected_no_findings: true` is preferred for these cases; any finding here surfaces a noise source.

| Profile | Corpus | Cases | Passed | Failed | Findings by family |
| --- | --- | ---: | ---: | ---: | --- |
| default | false_positive.json | 4 | 4 | 0 | _none_ |
| default | utility_matrix | 65 | 65 | 0 | medical-regex=2 |
| balanced | false_positive.json | 4 | 4 | 0 | _none_ |
| balanced | utility_matrix | 65 | 65 | 0 | medical-regex=2 |
| broad-pii | false_positive.json | 4 | 4 | 0 | _none_ |
| broad-pii | utility_matrix | 65 | 65 | 0 | gliner=1, medical-regex=2 |
| broad-pii-ml | false_positive.json | 4 | 4 | 0 | _none_ |
| broad-pii-ml | utility_matrix | 65 | 65 | 0 | gliner=1, medical-regex=2 |

## Per-detector-family signal vs noise

Historical counts of findings on the recorded five threat corpora, including the external ai4privacy benchmark (signal), versus the benign corpora (noise) for each detector family. The ratio is a coarse FP-load proxy: high signal with zero benign findings is the goal.

### default

| Detector family | Threat findings | Benign findings | Signal/noise |
| --- | ---: | ---: | --- |
| contextual-anchored | 55 | 0 | ∞ (no benign findings) |
| entropy | 147 | 0 | ∞ (no benign findings) |
| medical-regex | 32 | 2 | 16.0:1 |
| regex | 765 | 0 | ∞ (no benign findings) |

### balanced

| Detector family | Threat findings | Benign findings | Signal/noise |
| --- | ---: | ---: | --- |
| contextual-anchored | 55 | 0 | ∞ (no benign findings) |
| entropy | 147 | 0 | ∞ (no benign findings) |
| medical-regex | 32 | 2 | 16.0:1 |
| regex | 765 | 0 | ∞ (no benign findings) |

### broad-pii

| Detector family | Threat findings | Benign findings | Signal/noise |
| --- | ---: | ---: | --- |
| contextual-anchored | 50 | 0 | ∞ (no benign findings) |
| contextual-broad | 529 | 0 | ∞ (no benign findings) |
| entropy | 95 | 0 | ∞ (no benign findings) |
| gliner | 461 | 1 | 461.0:1 |
| medical-regex | 15 | 2 | 7.5:1 |
| regex | 723 | 0 | ∞ (no benign findings) |

### broad-pii-ml

| Detector family | Threat findings | Benign findings | Signal/noise |
| --- | ---: | ---: | --- |
| contextual-anchored | 2 | 0 | ∞ (no benign findings) |
| contextual-broad | 374 | 0 | ∞ (no benign findings) |
| entropy | 73 | 0 | ∞ (no benign findings) |
| gliner | 461 | 1 | 461.0:1 |
| medical-regex | 15 | 2 | 7.5:1 |
| openai_privacy_filter | 459 | 0 | ∞ (no benign findings) |
| regex | 709 | 0 | ∞ (no benign findings) |

## System-level detector recall

See `docs/system-recall.md` for per-detector recall and specificity against foundation fixtures, independent of profile composition. The release gates above are profile-level promise gates; system-recall.md is the engine-capability contract.

## Latency

Benchmark payload: `examples/openai_request.json` × 50 iterations.

| Profile | Throughput/sec | min ms | p50 ms | p95 ms | max ms | avg ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| default | 1312.7 | 0.627 | 0.706 | 1.114 | 1.209 | 0.762 |
| balanced | 1434.0 | 0.623 | 0.669 | 0.839 | 1.277 | 0.697 |
| broad-pii | 1.3 | 704.285 | 735.251 | 819.703 | 931.509 | 746.811 |
| broad-pii-ml | 0.8 | 1246.734 | 1290.166 | 1450.266 | 1614.817 | 1324.710 |

## Reproduce

Dependency-light profiles only:

```bash
docker compose run --rm cli eval-report --profile default --profile balanced --format markdown > EVAL.md
```

Current four-corpus matrix, including optional ML profiles (requires prepared optional dependencies and model cache):

```bash
docker compose --profile optional run --rm optional-cli eval-report --profile default --profile balanced --profile broad-pii --profile broad-pii-ml --format markdown > EVAL.md
```

Pass `--profile NAME` once per profile (default: `default`, `balanced`, `broad-pii`, `broad-pii-ml`), `--threat-dataset PATH` (repeatable; defaults: `piece_b_replay`, `medical_phi_replay`, `nemotron_pii`, `br_agentic_pii`), `--benign-dataset PATH` (repeatable; defaults: `false_positive`, `utility_matrix`), `--benchmark-payload PATH`, or `--iterations N` to override.

Each explicit `--threat-dataset` list replaces the defaults; it does not append to them. To include the external benchmark, first obtain the relevant dataset permissions and prepare an LSDF-format JSON file with `name` set to `ai4privacy_multilingual` at the ignored local path shown below. Keep the source data and local output out of commits and release artifacts. Include all four bundled corpora explicitly:

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

The local run evaluates the selected profiles against the supplied datasets. Matching historical numbers also requires the recorded dataset selection, policy, detector versions, and model configuration. See [Measured Protection](docs/measured-protection.md#operator-supplied-external-benchmark) and [Third-Party Notices](THIRD_PARTY_NOTICES.md).
