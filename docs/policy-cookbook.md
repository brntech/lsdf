# Policy Cookbook

Recipes recorded: 2026-05-06. Distribution guidance updated: 2026-09-08.

Use these recipes to move from observation to enforcement without surprising application teams. For detector-family trade-offs and measured profile costs, read `docs/detector-composition.md` before creating a custom policy with `detection.adapters` or `detection.entities`.

Complete [Installation](installation.md) before using the source-checkout commands below. Each scenario is an alternative starting point; `init --force` replaces the existing `.lsdf.env`, so retain any local provider, telemetry, and management settings when changing profiles. Optional profiles require the [model-cache preparation and active-family check](installation.md#optional-ml).

## Profile Inventory

`EVAL.md` records profiles that are directly comparable as containment tiers. The current default suite bundles four threat corpora: credential replay, synthetic medical PHI, Nemotron-PII, and BR-Agentic-PII. The earlier ai4privacy sample is not bundled; its metrics are historical external benchmark evidence.

| Profile | Use when | Why it is in EVAL |
|---|---|---|
| `default` | You want dependency-light enforcement for local agents and OpenAI-compatible gateways. | Baseline runtime posture: blocks inbound secrets, redacts hard identifiers, and observes low-noise generic identity. |
| `balanced` | You want dependency-light output PII redaction without optional ML models. | Same fast detector set as `default`, with broader outbound identity redaction. |
| `broad-pii` | You want local broad PII/PHI containment and can accept the GLiNER latency band. | Release-gated local ML tier; use the four bundled threat corpora and benign corpus reports. |
| `broad-pii-ml` | You want the bundled OpenAI privacy-filter adapter layered onto `broad-pii`. | Release-gated optional ML tier; use the four bundled threat corpora and benign corpus reports. |

These workflow profiles stay out of `EVAL.md` because they answer different operating questions:

| Profile | Use when | Why it is not an EVAL row |
|---|---|---|
| `monitor` | You need impact data before enforcing. | It intentionally observes decisions without transforms or blocks, so value-level containment would read as a failure by design. |
| `dev` | You need lower-friction local testing and JSON-shape checks. | It is a developer ergonomics posture that redacts where production profiles may block. |
| `strict` | RAG/tool-result prompt injection and dispatch surfaces are the main risk. | It adds the `prompt-injection` adapter and a threat model outside the PII/secret release-gate corpora. |
| `healthcare` | You need a PHI/MRN-oriented starting profile for clinical pilots. | Its five-corpus surface-containment promise includes external ai4privacy evidence; evaluating this profile with `eval-report` fails the gate if that required corpus is missing. Clinical fixtures and review are also needed. |

Domain packs are composable rule fragments, not standalone profiles. Add them to a base profile with `--domain-pack` or `LSDF_DOMAIN_PACKS`.

| Domain pack | Adds | Typical base profile |
|---|---|---|
| `healthcare` | PHI/MRN dispatch blocking and outbound healthcare identity handling. | `balanced` for dependency-light redaction, `broad-pii`/`broad-pii-ml` for stronger PII/PHI detection. |
| `financial` | Payment/account/tax-adjacent tokenization, dispatch blocking, and output redaction. | `default` or `balanced` for agent gateways; `strict` for tool-heavy financial workflows. |
| `enterprise-dlp` | Stronger secret/customer-confidential dispatch blocking and output handling. | `strict` for tool/webhook workflows; `default` or `balanced` for ordinary local apps. |

## Scenario Recipes

Each recipe starts from a committed profile or a base profile plus domain pack.
When a domain pack is listed, use the base profile's EVAL row as a baseline.
Packs change rules, actions, and surfaces, so they can change the reported
containment recall even when detector families stay the same. Evaluate the
combined policy with `eval --domain-pack` and representative fixtures.

| Scenario | Start with | EVAL row to verify | Why |
|---|---|---|---|
| Local coding agent with tools, reasoning, traces, or RAG context | `default` | `default` / `piece_b_replay`: recall 0.944, specificity 1.000 | Dependency-light protection for secrets before model calls, final content, tool-call arguments, reasoning fields, and traces. Generic identity stays mostly observe-only for low-friction local use. |
| Local agent where outbound identity must be redacted | `balanced` | `balanced` / `piece_b_replay`: recall 1.000, specificity 1.000 | Same fast detector families as `default`, but outbound EMAIL/PHONE/PERSON/ADDRESS/DOB-style findings are transformed instead of just observed. |
| Support chatbot or multilingual gateway with broad PII exposure | `broad-pii-ml` when optional model latency is acceptable; otherwise `broad-pii` | Recorded bundled `br_agentic_pii` recall: 1.000 for `broad-pii-ml`, 0.974 for `broad-pii`; specificity 1.000. Historical external `ai4privacy_multilingual` recall: 0.878 / 0.705, respectively | Prioritizes broad PII redaction. The bundled Portuguese corpus is agent-focused, not a universal multilingual benchmark. Historical ai4privacy results require separately licensed local data; validate the languages in your traffic. |
| Healthcare intake or clinical RAG pilot | `broad-pii` plus `healthcare` domain pack | `broad-pii` / `medical_phi_replay`: recall 0.944, specificity 1.000 | Uses the release-gated local broad-pii detector mix and adds PHI/MRN-focused workflow rules. Validate with clinical fixtures before regulated use. |
| Financial assistant, account-support workflow, or payment-adjacent tool use | `balanced` plus `financial` domain pack | `balanced` / `piece_b_replay`: recall 1.000, specificity 1.000 | Keeps dependency-light latency while adding payment/account/tax-adjacent rules. Use `strict` separately when prompt-injection risk is the primary concern. |

Copy-paste starting points:

```bash
# Local coding agent in front of LM Studio.
docker compose run --rm cli init --upstream lmstudio --profile default --output .lsdf.env --force
docker compose run --rm cli policy-validate --profile default
docker compose run --rm cli eval-report --profile default --threat-dataset evals/piece_b_replay.json --format markdown
docker compose --env-file .lsdf.env up -d gateway

# Outbound identity redaction for a local or provider-backed agent.
docker compose run --rm cli init --upstream lmstudio --profile balanced --output .lsdf.env --force
docker compose run --rm cli policy-validate --profile balanced
docker compose run --rm cli eval-report --profile balanced --threat-dataset evals/piece_b_replay.json --format markdown
docker compose --env-file .lsdf.env up -d gateway

# Broad PII support chatbot or multilingual gateway.
docker compose --profile optional run --rm optional-cli doctor --profile broad-pii-ml --format json
docker compose --profile optional run --rm optional-cli eval-report --profile broad-pii-ml --format markdown
docker compose run --rm cli init --upstream vllm --profile broad-pii-ml --output .lsdf.env --force
docker compose --env-file .lsdf.env --profile optional up gateway-ml

# Healthcare intake or clinical RAG pilot.
docker compose --profile optional run --rm optional-cli policy-validate --profile broad-pii --domain-pack healthcare
docker compose --profile optional run --rm optional-cli eval evals/medical_phi_replay.json --profile broad-pii --domain-pack healthcare --format markdown
docker compose --profile optional run --rm optional-cli protection-report --profile broad-pii --domain-pack healthcare --format markdown

# Financial account-support workflow.
docker compose run --rm cli policy-validate --profile balanced --domain-pack financial
docker compose run --rm cli protection-report --profile balanced --domain-pack financial --format markdown
docker compose run --rm cli eval evals/piece_b_replay.json --profile balanced --domain-pack financial --format markdown
```

## Operator-Supplied Benchmark and Healthcare Promise

The ai4privacy sample is not part of the distribution. Operators who have the appropriate upstream permissions may prepare an LSDF-format corpus named `ai4privacy_multilingual` at ignored `.lsdf/external-benchmarks/ai4privacy_multilingual.json`. Keep that data and local benchmark outputs out of Git and release artifacts. Explicit `--threat-dataset` options replace the default list; include all four bundled corpora when adding the external file:

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

The `healthcare` profile's five-corpus promise stays intact. A bundled-only healthcare evaluation fails its gate because external evidence is missing; supplying the file still requires every promised floor to pass. Adding the healthcare domain pack to `broad-pii` changes workflow rules and does not certify the standalone healthcare profile's gate. See [Measured Protection](measured-protection.md#operator-supplied-external-benchmark).

## Monitor-First Rollout

```bash
docker compose run --rm cli init --upstream demo --profile monitor \
  --audit-jsonl-path /workspace/.lsdf/audit.jsonl \
  --metrics-jsonl-path /workspace/.lsdf/metrics.jsonl \
  --output .lsdf.env --force
docker compose up -d demo-upstream
docker compose --env-file .lsdf.env up -d gateway
# Send representative chat traffic before reading telemetry.
docker compose run --rm cli audit-summary .lsdf/audit.jsonl
docker compose run --rm cli metrics-summary .lsdf/metrics.jsonl --format markdown
docker compose run --rm cli simulate-policy evals/basic.json --profile default --format markdown
```

Start with `monitor` when a team needs evidence before enforcement. Ordinary matched traffic is observed without sanitization or blocking in this mode. Review audit summaries and policy simulation output, then change the selected profile and recreate the gateway to enforce it. Keep upstream, telemetry, and management settings when updating the configuration; see the [Operational Rollout Guide](operational-rollout-guide.md).

## Optional ML Privacy Rollout

Use `broad-pii-ml` when you want the optional OpenAI privacy-filter integration on top of the local broad-PII stack. All LSDF-authored adapters remain Apache-2.0 source. Upstream detector packages and model weights retain their own licenses and are explicitly optional; see [Third-Party Notices](../THIRD_PARTY_NOTICES.md) for the exact reference models and upstream projects.

Prepare both model caches using [Optional ML installation](installation.md#optional-ml) before these checks. GLiNER is required for this profile; privacy-filter is configured as optional.

```bash
docker compose --profile optional build gateway-ml
docker compose run --rm cli policy-validate --profile broad-pii-ml
docker compose --profile optional run --rm optional-cli doctor --profile broad-pii-ml --format json
docker compose run --rm cli init --upstream vllm --profile broad-pii-ml --output .lsdf.env --force
docker compose --env-file .lsdf.env --profile optional up gateway-ml
```

Start with representative fixtures and audit review before enforcing new traffic classes. The recorded combined ML results require the detector families used in that measurement. A successful doctor exit does not prove privacy-filter loaded: `broad-pii-ml` may continue with the broad-pii stack when that optional family is unavailable. Inspect the JSON detector-family list for both `gliner` and `openai_privacy_filter`, then validate coverage and latency on representative traffic. `policy-validate` does not load model weights. Run one gateway at a time because the services share host loopback port 8080, and check shell `LSDF_PROFILE` or `LSDF_POLICY` overrides before changing profiles.

## Output Redaction

Use `default` for the normal first enforcement step. It blocks high-risk inbound secrets and redacts releasable output content.

```bash
docker compose run --rm cli policy explain policies/default.yaml --format markdown
docker compose run --rm cli explain examples/quickstart/response_redact_request.json --unknown-surface output.content --format text
```

## Strict Tool-Call Blocking

Use `strict` or add `enterprise-dlp` when tool calls, webhooks, or agent dispatch surfaces are the main risk.

```bash
docker compose run --rm cli protection-report --profile strict --domain-pack enterprise-dlp --format markdown
```

## Trace And Log Sanitation

Sanitize trace/log/span payloads with `logs.traces` semantics.

```bash
docker compose run --rm cli sanitize-observability examples/quickstart/observability.json
docker compose run --rm cli explain examples/quickstart/observability.json --unknown-surface logs.traces --format text
```

## OpenRouter Gateway

```bash
docker compose run --rm cli init --upstream openrouter --output .lsdf.env --force
docker compose --env-file .lsdf.env up gateway
```

Set upstream provider keys outside committed files. Application clients still use `http://localhost:8080/v1`.

## LiteLLM Gateway

```bash
docker compose run --rm cli init --upstream litellm --output .lsdf.env --force
docker compose --env-file .lsdf.env up gateway
```

Recommended topology is `app -> LSDF gateway -> LiteLLM Proxy -> provider fleet`.

## Operator Vocabulary (`replace`, `hash`, `encrypt`)

Beyond the bundled `redact | mask | tokenize | block` set, three Presidio-anonymizer-parity operators are available with per-rule parameters validated at policy load.

| Action | Per-rule parameter | Output shape | Notes |
|---|---|---|---|
| `replace` | `replacement: <string>` (required) | the operator-supplied literal | Use when downstream consumers want a stable named placeholder (`[CUSTOMER]`, `<<EMAIL>>`). |
| `hash` | `hash_algo: sha256 \| sha512 \| blake2b` (default `sha256`) | `<{ENTITY}:HASH:<algo>=<hex16>>` | Deterministic — same input + algo always produces the same output, so audit events and traces correlate without exposing the raw value. Truncated to 64 bits for in-line readability. |
| `encrypt` | `encrypt_key_env: <env var name>` (required) | `<{ENTITY}:ENC:<fernet-token>>` | Reversible. The env var must hold a urlsafe-base64 32-byte Fernet key; generate one with `docker compose run --rm cli vault keygen`. The transform raises `ValueError` if the env var is unset or malformed at request time. |

Examples:

```yaml
# Stable named placeholders for downstream display.
- id: customer-name-redaction
  match: {entity: PERSON, surface: output.content}
  action: replace
  replacement: "[CUSTOMER]"

# Deterministic correlation token without revealing the raw value.
- id: ssn-correlation
  match: {entity: US_SSN, surface: output.content}
  action: hash
  hash_algo: sha256

# Reversible encryption for cases where downstream operators need the original
# value back (with the key). Suitable for storing the ciphertext in observability
# without exposing plaintext to log readers without the key.
- id: financial-account-encrypt
  match: {entity: BANK_ACCOUNT, surface: output.content}
  action: encrypt
  encrypt_key_env: LSDF_FINANCIAL_ENCRYPT_KEY
```

The `encrypt` operator requires the env var to be set in every environment that runs the firewall. Generate the key once and distribute it via your existing secret-management path. A Compose `--env-file` supplies interpolation values; it does not forward arbitrary variable names. For a one-off CLI container, pass `-e LSDF_FINANCIAL_ENCRYPT_KEY` to `docker compose run`. For a persistent gateway, save an override such as `compose.encrypt.yaml`:

```yaml
services:
  gateway:
    environment:
      LSDF_FINANCIAL_ENCRYPT_KEY: "${LSDF_FINANCIAL_ENCRYPT_KEY:?Supply the encryption key securely}"
```

Include that override whenever recreating the gateway: `docker compose --env-file .lsdf.env -f docker-compose.yml -f compose.encrypt.yaml up -d gateway`. Prebuilt users use `-f compose.release.yaml` as the first file. For the source ML service, use `gateway-ml` as the override service name. Do not put a key literal in the YAML or committed files.

Operator parameters are mutually exclusive with the action they target — supplying `replacement` on a `redact` rule, or `hash_algo` on an `encrypt` rule, fails policy load with a clear error message naming the rule id.

## Per-Rule `on_fail` Overrides

The policy-level `mode: monitor | redact | block` switch is repo-wide; `on_fail` lets you override per rule when a single posture is too coarse. Each rule can carry one of five values:

| `on_fail` | What it does |
|---|---|
| `mask` | Apply the rule's `action` transform (default; explicit form). Equivalent to omitting `on_fail`. |
| `observe` | Log the decision in the audit trail; do not apply the transform; do not block. The per-rule analog of `mode: monitor`. |
| `block` | Set `blocked=true` regardless of the rule's `action`, AND apply the rule's transform so the halted-but-structurally-still-present payload is raw-value-safe for any downstream logger / tracer that handles the response. Useful for "any time this rule fires, halt the request" overrides on otherwise gentle actions. Escalates above the policy mode. |
| `reask` | Apply the transform AND surface a `reask_hint: true` flag in the audit event. A wrapping orchestration layer (LiteLLM router, agent supervisor) can branch on the flag to re-issue with a redaction prefix. LSDF itself does not retry. |
| `exception` | Raise `lsdf.PolicyEnforcementError` from `Firewall.inspect`. For "this should never happen, halt loudly" rules — the gateway returns a safe 403 for request inspection or 502 for response inspection; after streaming starts it emits a terminal error event. |

Common shapes:

```yaml
# Redact-by-default policy with one observe-only rule for a noisy rollout candidate.
action:
  mode: redact
  rules:
    - id: redact-pii-in-output
      match: {entity_any_of: [EMAIL, PHONE, PERSON], surface: output.content}
      action: redact
    - id: medical-regex-pilot
      match: {entity_in_category: PHI, surface: input.rag_context}
      action: tokenize
      on_fail: observe   # audit only while collecting signal
```

```yaml
# Monitor-mode policy with one rule that still blocks (the hard halt).
action:
  mode: monitor
  rules:
    - id: known-credential-shapes
      match: {entity_in_category: SECRET, surface: any}
      action: redact
      on_fail: block     # always halt the request, regardless of mode
```

`on_fail: exception` and `on_fail: block` are escalations: they fire louder than the policy mode. `on_fail: observe` is a de-escalation: the rule audits but does not enforce. `on_fail: reask` applies the transform and surfaces a hint for the orchestration layer to re-issue.

## False-Positive Reduction

1. Start with `monitor`.
2. Summarize audit events.
3. Compare candidate policies with `simulate-policy`.
4. Prefer domain packs over broad custom rules.
5. Move to `default` or `strict` only after representative fixtures pass.

## Healthcare Profile Limits

`healthcare` and the built-in `medical-regex` detector are lightweight starting points. They are not full HIPAA de-identification. Use dedicated medical NER, clinical fixtures, and human review for regulated PHI workflows.
