# Detector Composition Guide

Evidence recorded: 2026-05-06 to 2026-05-07. Distribution guidance updated: 2026-09-08.

Use this guide to choose a detector mix before you edit `enabled_families`.
Detector families find candidate sensitive data; policy rules decide whether
those findings are logged, redacted, tokenized, or blocked. That means two
profiles can use the same detector mix but produce different containment
results because their actions differ.

Recorded source cells (these are historical measurements, not a fresh run after the dataset distribution change):

- `EVAL.md` generated 2026-05-07T01:05:55Z for value-level recall,
  specificity, benign findings, and detector-family signal/noise.
- `docs/performance.md` generated 2026-05-07T00:56:51Z for CPU latency.

## Fast Picks

| Workload | Start with | Detector mix | Measured signal | Main trade-off |
| --- | --- | --- | --- | --- |
| Local coding agent, secrets, tool calls, traces | `default` | `regex + entropy + medical-regex + contextual-anchored` | Credential replay recall 0.944, FP case rate 0.000, small-chat p50 9.284 ms | Generic PII is mostly logged, not broadly redacted. |
| Local agent where outbound identity should be redacted | `balanced` | `regex + entropy + medical-regex + contextual-anchored` | Credential replay recall 1.000, FP case rate 0.000, small-chat p50 0.446 ms | Same detector set as `default`; stronger value containment comes from actions. |
| Broad PII/PHI containment without OpenAI privacy-filter | `broad-pii` | `regex + entropy + medical-regex + contextual-anchored + contextual-broad + gliner` | Recall 1.000 / 0.944 / 0.680 / 0.974 across the four bundled threat corpora, FP case rate 0.000 | Small-chat p50 rises to 429.095 ms; RAG-heavy p50 to 17535.148 ms. |
| Broad PII/PHI plus the bundled reference ML detector | `broad-pii-ml` | `broad-pii + openai_privacy_filter` | Recall 1.000 / 0.981 / 0.713 / 1.000, FP case rate 0.000 | Small-chat p50 rises to 2504.289 ms; RAG-heavy p50 to 27679.987 ms and requires model-cache readiness. |
| RAG/tool-result prompt-injection risk | `strict` | `regex + entropy + medical-regex + contextual-anchored + prompt-injection` | Not a release-eval row; validate with representative fixtures | Adds prompt-injection detection, not broad PII recall. |
| Healthcare or financial workflow | Base profile plus domain pack | Detection from the base profile, rules from `healthcare` or `financial` | Use the base profile's EVAL row; packs do not add detector families | Domain packs alter actions and surfaces, not detector recall. |

The four bundled threat-corpus recall values are ordered as `piece_b_replay` /
`medical_phi_replay` / `nemotron_pii` / `br_agentic_pii`.
For `broad-pii` and `broad-pii-ml`, the first, second, and fourth corpora are
release-gated; Nemotron-PII provides additional characterization for those
span-scope profiles. The values are retained per-corpus cells from the recorded
run. The ai4privacy sample is no longer bundled; its historical external
benchmark recall is recorded separately below.

| Profile | Historical external `ai4privacy_multilingual` recall |
| --- | ---: |
| `default` | 0.128 |
| `balanced` | 0.326 |
| `broad-pii` | 0.705 |
| `broad-pii-ml` | 0.878 |

Those external measurements require an appropriately licensed operator-supplied
file under ignored `.lsdf/external-benchmarks/` to reevaluate. Healthcare retains
its five-corpus promise and fails its gate if the required external corpus is
omitted. See [Measured Protection](measured-protection.md#operator-supplied-external-benchmark)
for the full four-plus-external command; explicit `--threat-dataset` options
replace the defaults.

## Profile Mixes

| Profile | Detector families | Value-level recall by corpus | Benign specificity / FP case rate | EVAL p50 | Performance p50, small / RAG-heavy |
| --- | --- | --- | --- | ---: | --- |
| `default` | `regex`, `entropy`, `medical-regex`, `contextual-anchored` | 0.944 / 0.593 / 0.077 / 0.205 | 1.000 / 0.000 | 0.798 ms | 9.284 ms / 56.040 ms |
| `balanced` | `regex`, `entropy`, `medical-regex`, `contextual-anchored` | 1.000 / 0.611 / 0.267 / 0.205 | 1.000 / 0.000 | 0.918 ms | 0.446 ms / 57.938 ms |
| `broad-pii` | `regex`, `entropy`, `medical-regex`, `contextual-anchored`, `contextual-broad`, `gliner` | 1.000 / 0.944 / 0.680 / 0.974 | 1.000 / 0.000 | 805.407 ms | 429.095 ms / 17535.148 ms |
| `broad-pii-ml` | `regex`, `entropy`, `medical-regex`, `contextual-anchored`, `contextual-broad`, `gliner`, `openai_privacy_filter` | 1.000 / 0.981 / 0.713 / 1.000 | 1.000 / 0.000 | 1426.715 ms | 2504.289 ms / 27679.987 ms |

Read the table as profile-level containment, not per-family recall. LSDF's
release corpora annotate values and expected entity types, while overlap
resolution can assign one surviving finding among several detector candidates.
`EVAL.md` therefore reports value-level recall for profiles and signal/noise
finding counts for families.

## Family Roles

| Family | Catches | Appears in | Current evidence note | Cost and FP notes |
| --- | --- | --- | --- | --- |
| `regex` | Structured secrets and anchored identifiers: cloud/API keys, passwords, JWTs, US_SSN, BR_CPF, credit cards, email, phone, MRN, IBAN, anchored person/address/DOB/account labels. | All release profiles. | Profile-level rows above are recorded containment evidence; family signal/noise counts are in `EVAL.md`. | Fastest, dependency-light baseline. Best for local agents and credential leaks. |
| `entropy` | High-entropy credential-like strings that do not self-identify with a known prefix. | All release profiles. | Profile-level rows above are recorded containment evidence; family signal/noise counts are in `EVAL.md`. | Fast supplement to regex. It is not a general PII detector. |
| `medical-regex` | Context-gated clinical patterns such as ICD-like codes, lab values, diagnosis text, and medication-dosage shapes. | All release profiles and healthcare workflows. | Profile-level rows above are recorded containment evidence; family signal/noise counts are in `EVAL.md`. | Lightweight PHI support, not full HIPAA de-identification or medical NER. |
| `contextual-anchored` | Inline XML contact tags plus high-precision label/value secrets and identity-document fields. | All profiles. | Included in the dependency-light baseline; family signal/noise counts are in `EVAL.md`. | Baseline coverage with no model cache; focused on low-FP anchored evidence. |
| `contextual-broad` | Broad PII/PHI field labels and output-only quasi-identifier shapes. | `broad-pii`, `broad-pii-ml`. | Major recall lift without a model cache; family signal/noise counts are in `EVAL.md`. | Stronger local broad PII detection, but still paired with GLiNER in release-gated profiles. |
| `gliner` | Local ML NER for PERSON, ADDRESS, DATE_OF_BIRTH, PHI subtypes, financial and similar PII labels. | `broad-pii`, `broad-pii-ml`. | Profile-level rows above are recorded containment evidence; family signal/noise counts are in `EVAL.md`. | The main local latency cliff. Use when broad PII recall matters more than sub-ms response time. |
| `openai_privacy_filter` | Bundled optional reference ML detector for broader PII shapes and multilingual evidence. | `broad-pii-ml`. | Profile-level rows above are recorded containment evidence; family signal/noise counts are in `EVAL.md`. | Adds recall on Nemotron-PII, multilingual, and BR-Agentic corpora but roughly doubles broad-pii small-payload latency on CPU. Requires optional image/model readiness. |
| `prompt-injection` (`xpia`) | Indirect prompt-injection heuristics for retrieved RAG and tool-result surfaces. | `strict`. | Not in the release PII/secret EVAL matrix. | Use for RAG/tool workflows; validate with prompt-injection fixtures rather than PII recall. |
| `presidio` | External Presidio analyzer output normalized into LSDF findings. | Optional adapter contract, not a shipped release profile. | Not in the release EVAL matrix. | Use when your environment already depends on Presidio and can own its dependency/FP profile. |

Benign specificity is computed as one minus the benign case failure rate.
Benign findings still appear as noise candidates in the family table even when
policy behavior keeps the benign case passing.

## Optional Dependencies and Licensing

All LSDF-authored adapter code remains Apache-2.0 and is included in the open-source core. GLiNER, Presidio, and OpenAI privacy-filter are explicitly optional integrations. Upstream Python packages and downloaded model weights retain their own licenses; selecting an adapter does not relicense them. Consult the exact model cards and upstream projects in [Third-Party Notices](../THIRD_PARTY_NOTICES.md) when choosing or replacing a model.

## How To Compose Safely

1. Start with the policy action you need.
   `default` and `balanced` use the same dependency-light detector families;
   `balanced` contains more output identity values because its rules redact
   outbound generic identity, not because it detects a different family.

2. Add detector families only when the workload needs their recall.
   For broad PII/PHI, move to `broad-pii` before inventing a custom mix.
   It is the local release-gated row for span-scope broad PII redaction on
   the piece_b, medical PHI, and BR-Agentic promise corpora; its full
   characterization cells are in `EVAL.md`.

3. Add `openai_privacy_filter` only when the extra recall justifies the
   optional runtime.
   `broad-pii-ml` lifts medical PHI recall from 0.944 to 0.981,
   Nemotron-PII recall from 0.680 to 0.713, and BR-Agentic recall from
   0.974 to 1.000 in the recorded EVAL. Historical external ai4privacy
   recall rose from 0.705 to 0.878. In the recorded latency run, while small-chat p50 rises from 429.095 ms to 2504.289 ms
   and RAG-heavy p50 rises from 17535.148 ms to 27679.987 ms on CPU.

4. Use domain packs for workflow policy, not detector recall.
   `healthcare`, `financial`, and `enterprise-dlp` add rules and priorities on
   top of a base profile. They do not add detector families by themselves.

5. Validate custom mixes in monitor mode first.
   Run representative traffic with `monitor`, inspect raw-value-safe audit
   summaries, then simulate or enforce the target profile.

## Custom Mix Example

Prefer existing profiles first. If you need a custom policy, keep the detector
list explicit and document why each family is present:

```yaml
version: 0.2
name: custom-local-pii
detection:
  adapters: [contextual-broad]
  entities:
    - EMAIL
    - PHONE
    - PERSON
    - DATE_OF_BIRTH
    - ADDRESS

action:
  mode: redact
  rules:
    - id: redact-output-identity
      match:
        entity_any_of: [EMAIL, PHONE, PERSON, DATE_OF_BIRTH, ADDRESS]
        surface_any_of: [output.content, output.stream_chunk]
      action: redact
      severity: medium
      priority: 60

audit:
  store_raw_values: false
  store_redacted_evidence: true
  include_policy_decision: true
```

After saving the custom policy as `policies/custom-local-pii.yaml`, prove the
mix before serving traffic. Use a representative fixture file for
`simulate-policy` so expected entities, surfaces, and actions match your custom
rules:

```bash
docker compose run --rm cli policy-validate policies/custom-local-pii.yaml
docker compose run --rm cli protection-report --policy policies/custom-local-pii.yaml --format markdown
docker compose run --rm cli benchmark examples/openai_request.json --policy policies/custom-local-pii.yaml --iterations 50 --format markdown
docker compose run --rm cli simulate-policy path/to/representative-fixtures.json --policy policies/custom-local-pii.yaml --format markdown
```

For release-profile comparisons, use the committed reports:

```bash
docker compose run --rm cli eval-report --profile default --profile balanced --format markdown
docker compose --profile optional run --rm optional-cli eval-report --profile broad-pii --profile broad-pii-ml --format markdown
```
