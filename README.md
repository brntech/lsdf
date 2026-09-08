# LLM Sensitive Data Firewall

**Open-source sensitive-data firewall for local and OpenAI-compatible LLM apps.**

LSDF is a Docker-first OpenAI-compatible proxy you put between your app and the model. It is built for developers running local LLM agents, tool-calling apps, RAG workflows, or provider gateways who need secrets, PII, PHI, reasoning fields, tool-call arguments, streaming chunks, and trace/log payloads inspected before they leak.

Background article: [The Safety Map](https://www.linkedin.com/pulse/safety-map-what-does-doesnt-transfer-llm-handling-al-zubaidi-g0v8e). See also the [research papers](#research-and-publications).

## Start Here

Install [Docker with Compose](https://docs.docker.com/compose/install/) and Git, and start Docker with Linux containers. Get the release source and enter its directory:

```bash
git clone --branch v0.3.2 --depth 1 https://github.com/brntech/lsdf.git
cd lsdf
docker compose version
```

You can also extract `lsdf-0.3.2-source.zip` from the [release downloads](https://github.com/brntech/lsdf/releases/tag/v0.3.2) and open its folder. These commands build images locally; no separate image pull is needed. The first build needs internet access and may take several minutes. For a prebuilt gateway without a source checkout, use the [installation guide](docs/installation.md#prebuilt-release-image).

Try the self-contained demo; no model server or provider key is required:

```bash
docker compose --profile demo up --build --abort-on-container-exit --exit-code-from demo-runner demo-runner
docker compose --profile demo down
```

To use a real model, start its server first, then configure LSDF (this example uses LM Studio):

```bash
docker compose build cli
docker compose run --rm cli init --upstream lmstudio --output .lsdf.env
docker compose --env-file .lsdf.env up --build -d gateway
```

Point your application at `http://localhost:8080/v1`. With the OpenAI SDK already installed in your application's environment:

```python
from openai import OpenAI

client = OpenAI(base_url="http://localhost:8080/v1", api_key="local-dev-key")
```

Use `--upstream vllm`, `litellm`, or `openrouter` for those providers; `custom` also requires `--upstream-base-url`. Edit `.lsdf.env` for your endpoint and provider key before starting. LSDF forwards `/v1/chat/completions`; the placeholder client key above is not upstream authentication or gateway access control.

The [installation guide](docs/installation.md) covers a first chat request, supported image/platform choices, host networking, PowerShell settings, optional models, stopping, and upgrades. Choose a starting policy from the [policy cookbook](docs/policy-cookbook.md).

## What LSDF Protects

Most privacy tools inspect only prompt and response text. LSDF treats the whole LLM execution path as risky:

- Requests are scanned before they reach the model.
- Responses are scanned before they reach the user.
- Streaming content is held briefly, inspected, then released only after it passes the rolling risk window.
- Streamed tool-call arguments are assembled and inspected before raw fragments can reach clients.
- Trace/log/span payloads can be sanitized outside the gateway.
- Indirect prompt injection on retrieved RAG and tool-result surfaces is blocked under the `strict` profile.
- Audit and reports are raw-value-safe by default.

LSDF is local-first, dependency-light by default, and designed to make privacy behavior measurable. It also includes OpenRouter and LiteLLM presets, provider playbooks, demo-media assets, policy explanation, sample proof artifacts, and release-ready operational guidance.

For the standalone gateway image in v0.3.2, with required policy fixtures and first-party proof matrices, see [Production Operations](docs/production-operations.md#standalone-runtime-image). Both runtime variants start with the dependency-light `default` profile; ML profiles require explicit selection and a prepared cache. The lightweight runtime leaves out heavy detector dependencies, model weights, and external benchmark corpora; the development Compose services support full evaluations and demos.

## Open Source and Optional Integrations

LSDF's core and all LSDF-authored detector adapters are available under [Apache-2.0](LICENSE), including the GLiNER, Presidio, and OpenAI privacy-filter integrations. Their upstream packages and model weights retain their own licenses and notices. These integrations are explicitly optional; the default runtime does not need their packages or weights. See [Third-Party Notices](THIRD_PARTY_NOTICES.md) for dataset attribution and the exact reference model cards.

## Five-Minute Quickstart

LSDF work is container-only. Do not install LSDF dependencies, optional detector packages, or model tooling into the desktop host Python environment.

The demo starts the upstream and gateway, then proves request blocking, response redaction, streaming redaction, streamed tool-call blocking, trace sanitation, health, metrics, audit summary, and metrics summary without printing raw sensitive values.

Generate a shareable proof bundle:

```bash
docker compose run --rm cli proof-bundle --output .lsdf/proof --audit-jsonl-path .lsdf/demo/audit.jsonl --metrics-jsonl-path .lsdf/demo/metrics.jsonl --format markdown
```

Show the safe narration script for a one-minute proof video:

```bash
docker compose run --rm cli demo-script --format markdown
```

A real captured demo transcript ships in `examples/demo-media/golden-demo.captured.txt`. The matching asciinema cast (`examples/demo-media/golden-demo.cast`) can be replayed locally with `asciinema play` or embedded in docs via [asciinema-player](https://github.com/asciinema/asciinema-player). Refresh the artifacts whenever the demo evolves:

```bash
bash scripts/record-demo.sh                  # refresh captured.txt + deterministic cast
bash scripts/record-demo.sh --with-gif       # also render a GIF (requires asciinema + agg)
```

Manual quickstart commands are still available:

```bash
docker compose build
docker compose run --rm cli demo
docker compose run --rm cli doctor
docker compose run --rm cli init --upstream demo --audit-jsonl-path /workspace/.lsdf/audit.jsonl --metrics-jsonl-path /workspace/.lsdf/metrics.jsonl --output .lsdf.env --force
docker compose run --rm cli explain examples/quickstart/request_block.json
docker compose run --rm cli sanitize-observability examples/quickstart/observability.json
docker compose run --rm cli audit-summary examples/quickstart/audit.jsonl
docker compose run --rm cli protection-report --format markdown
docker compose run --rm cli policy explain policies/default.yaml --format markdown
```

Run the demo upstream and LSDF gateway:

```bash
docker compose up demo-upstream
```

In another terminal:

```bash
docker compose --env-file .lsdf.env up gateway
```

Then point OpenAI-compatible clients at `http://localhost:8080/v1`. The demo upstream intentionally leaks sensitive data so you can see LSDF block unsafe requests, redact unsafe responses, sanitize streaming chunks, block unsafe tool-call arguments, and write raw-value-safe audit events.

After the gateway is running:

```bash
docker compose run --rm cli quickstart-report --gateway-base-url http://gateway:8080 --audit-jsonl-path .lsdf/audit.jsonl --metrics-jsonl-path .lsdf/metrics.jsonl --format markdown
docker compose run --rm cli smoke --gateway-base-url http://gateway:8080
```

## Research and Publications

LSDF is developed by Broadnet and productises the sensitive-data leakage research published by its co-founder, who advised the project.

- [How to Evaluate an LLM for Sensitive Data Safety Before Deploying It](https://doi.org/10.5281/zenodo.19574049) (2026). DOI: `10.5281/zenodo.19574049`.
- [The Safety Map: What Does and Doesn't Transfer in LLM Sensitive-Data Handling](https://doi.org/10.5281/zenodo.19688433) (2026). DOI: `10.5281/zenodo.19688433`.

## Proven Against Real-World Leaks

Release-gated profiles must hold value-level recall **>= 0.90** on their stated promise corpora and benign specificity **>= 0.95**. The recorded `EVAL.md` snapshot reports `broad-pii` and `broad-pii-ml` passing on piece_b_replay, medical_phi_replay, and BR-Agentic-PII. Nemotron-PII is bundled characterization evidence for those broad tiers. The healthcare profile retains its five-corpus promise, including the operator-supplied ai4privacy benchmark: evaluating healthcare with only the bundled corpora fails its gate because that required corpus is missing.

```bash
docker compose --profile optional run --rm optional-cli eval-report --profile broad-pii --profile broad-pii-ml --format markdown
```

LSDF bundles four default threat corpora: a sanitized 40-case credential-leak replay (`piece_b_replay`), synthetic clinical PHI (`medical_phi_replay`), NVIDIA broad English PII (`nemotron_pii`), and Brazilian Portuguese banking-agent PII (`br_agentic_pii`), plus benign corpora. The earlier ai4privacy multilingual sample is no longer bundled. Its committed aggregate metrics are labeled historical external benchmark evidence. Operators who have obtained the appropriate dataset permissions may supply a local LSDF-format copy under ignored `.lsdf/external-benchmarks/`; see [Measured Protection](docs/measured-protection.md#operator-supplied-external-benchmark) for the complete command. The dependency-light `default` profile stays narrower for low-friction adoption.

Reproduce on your own machine:

```bash
docker compose --profile optional run --rm optional-cli eval evals/piece_b_replay.json --profile broad-pii-ml --format markdown
```

A 6-case follow-up corpus (`evals/piece_b_replay_ml_pii.json`) targets ML-only PII shapes the regex layer cannot catch: international phone formats and multi-cultural given names. Across all four candidate `score_threshold` values (0.50 / 0.70 / 0.85 / 0.95), `sensitive_values_leaked_after` stays at **0**. See `docs/fp-lever-sweep-2026-04-29.md` for the full sweep.

The standard evaluation and comparison commands use the four bundled threat corpora and produce reports without raw fixture values. `EVAL.md` and `docs/comparative-protection.md` retain explicitly labeled historical external benchmark metrics; reproducing those rows requires the separately licensed local benchmark. `docs/performance.md` records latency on its stated payloads.

## Multilingual PII Detection

Tested across three languages with native PII shapes, the `broad-pii-ml` profile detected names, phone numbers, addresses, emails, and national-ID-shaped identifiers without language-specific configuration:

- **Arabic**: name, phone, address.
- **Chinese**: name, national ID (returned as `account_number`), phone.
- **Spanish**: name, email, address.

These were short-input smoke probes. Long multilingual inputs and mixed-script prose remain uncharacterized. Add representative language fixtures before relying on automated enforcement for any specific locale. Source framing: `docs/measured-protection.md`.

## Detection Coverage At A Glance

The dependency-light default ships **49 deterministic regex recognizers** (AWS access/secret/session keys, GitHub tokens, JWTs with payload-claim validation, Stripe keys, OpenAI/Anthropic keys, PEM private keys, Slack tokens, Google API keys, GCP service accounts and OAuth, Twilio, Mailgun, SendGrid, Datadog, NPM, PyPI, Discord, Azure storage keys and SAS tokens, DigitalOcean, Heroku, Linode, Square, Braintree, Atlassian, DB connection URLs, Bearer tokens, plus generic credential, US_SSN and BR_CPF, credit-card-with-Luhn, email, NANP and Brazilian phone, Brazilian state/CEP address, Portuguese chat-name context, MRN, IBAN, and anchored name/address/DOB/bank-account fields). Pattern recognizers support a context-word boost (`context_words`/`context_required`) used to gate the medical PHI patterns against benign technical prose.

Additional families:

- `entropy`: supplementary high-entropy credential heuristic (covers password-shaped strings the regex layer doesn't anchor).
- `medical-regex`: diagnosis text, ICD-like codes, lab values, medication-dosage patterns. Context-required against clinical anchors.
- `prompt-injection` (internal family `xpia`): opt-in indirect prompt-injection detector (instruction-override phrases, role-tag impersonation, hidden HTML/style blocks, zero-width runs, long base64 blobs, exfiltration phrases). Wired into `strict` to block on `input.rag_context` / `input.tool_results`.
- `contextual-anchored`: narrow label/value and tagged-PII patterns, active by default.
- `contextual-broad`: broader PII context for profiles that explicitly enable it.
- `gliner`, `presidio`, `openai_privacy_filter`: ML adapters. PERSON findings are filtered against a static public-figure deny-list at the registry level; extend at deploy time with `LSDF_PERSON_DENY_LIST_EXTRA`.

Policy rules can match whole subtype families with `entity_in_category:` (for example `SECRET`, `PHI`, `STRONG_ID`, or `INTERNAL_ID`), a category-level composition layer Presidio does not provide directly.

See `docs/detector-composition.md` for profile and detector-mix guidance, `EVAL.md` for the per-release signal-vs-noise snapshot, and `docs/performance.md` for the latency table.

## Measured Protection

The dependency-light default is designed for fast local adoption. For stronger PII plus secret detection, LSDF also ships an optional ML-backed path using OpenAI privacy-filter as a reference adapter plus LSDF's entropy scanner.

The `broad-pii-ml` profile layers OpenAI privacy-filter with LSDF entropy and structured detectors because different detector families catch different credential and PII shapes. This detector composition does not establish a blanket detection guarantee; production rollouts should run representative fixtures and monitor-mode audit review.

See `docs/measured-protection.md`, `docs/comparative-protection.md`, and `docs/detector-adapter-contract.md` for the evidence framing, Presidio/regex-only comparison, and pluggable detector contract.

## Daily Commands

Run from the source checkout after building the CLI image. Create the ignored `.lsdf/` directory if it does not exist; generated reports below do not overwrite the published snapshots.

```bash
docker compose run --rm cli doctor --format json
docker compose run --rm cli init --upstream lmstudio --output .lsdf.env
docker compose run --rm cli scan examples/openai_request.json
docker compose run --rm cli explain examples/openai_request.json --format text
docker compose run --rm cli benchmark examples/openai_request.json --iterations 50 --format markdown
docker compose run --rm cli protection-report --format markdown
docker compose run --rm cli eval-report --profile default --profile balanced --format markdown > .lsdf/eval-current.md
docker compose run --rm cli latency-table --format markdown > .lsdf/latency-current.md
docker compose run --rm cli adapters list
docker compose run --rm cli entities list
docker compose run --rm cli policy explain --profile default --format markdown
docker compose run --rm cli metrics-summary .lsdf/metrics.jsonl --format markdown
docker compose run --rm cli vault keygen
docker compose run --rm cli vault check --vault-path .lsdf/vault.sqlite
docker compose run --rm cli simulate-policy evals/basic.json --format markdown
docker compose run --rm cli security-report --format markdown
docker compose run --rm cli proof-bundle --output .lsdf/proof --format markdown
docker compose run --rm test
```

## Gateway Configuration

Run against a local OpenAI-compatible endpoint:

```bash
LSDF_PROFILE=default \
LSDF_STREAM_HOLDBACK_CHARS=512 \
LSDF_AUDIT_JSONL_PATH=/workspace/.lsdf/audit.jsonl \
LSDF_METRICS_ENABLED=true \
LSDF_METRICS_JSONL_PATH=/workspace/.lsdf/metrics.jsonl \
LSDF_UPSTREAM_BASE_URL=http://host.docker.internal:8000 \
  docker compose up gateway
```

Common upstreams:

```bash
# Demo service inside this Compose project
LSDF_UPSTREAM_BASE_URL=http://demo-upstream:8091

# Local vLLM from the LSDF container
LSDF_UPSTREAM_BASE_URL=http://host.docker.internal:8000

# LM Studio from the LSDF container
LSDF_UPSTREAM_BASE_URL=http://host.docker.internal:1234

# Generic OpenAI-compatible provider
LSDF_UPSTREAM_BASE_URL=https://provider.example
LSDF_UPSTREAM_API_KEY=your-provider-key

# LiteLLM Proxy
LSDF_UPSTREAM_BASE_URL=http://host.docker.internal:4000

# OpenRouter
LSDF_UPSTREAM_BASE_URL=https://openrouter.ai/api/v1
```

Optional ML-backed gateway:

```bash
docker compose --profile optional build gateway-ml optional-cli
docker compose run --rm cli policy-validate --profile broad-pii-ml
docker compose --profile optional run --rm optional-cli doctor --profile broad-pii-ml
LSDF_UPSTREAM_BASE_URL=http://host.docker.internal:8000 \
  docker compose --profile optional up gateway-ml
```

`gateway` and `gateway-ml` both bind `localhost:8080`; run one at a time or remap ports. `gateway-ml` uses the heavier optional image, Docker-managed model cache, and `LSDF_PROFILE=broad-pii-ml` by default. OpenAI privacy-filter is the bundled reference adapter, not the only possible ML detector.

Prepare both GLiNER and privacy-filter models using the [optional ML setup](docs/installation.md#optional-ml) before running this sequence. Both default to cache-only loading. Missing required GLiNER produces a detector-unavailable diagnostic. GLiNER is required by the broad profile, while privacy-filter may be skipped when unavailable; a successful doctor exit alone does not prove that the full ML stack loaded. Inspect the reported detector families.

Policy selection precedence for the gateway is: explicit `--policy`, `LSDF_POLICY`, explicit `--profile`, `LSDF_PROFILE`, then `default`. If no explicit policy is supplied, `LSDF_DOMAIN_PACKS=healthcare,financial` compiles domain-pack rules into the selected profile. Use the upstream service root as `LSDF_UPSTREAM_BASE_URL`; the gateway forwards OpenAI-compatible `/v1/chat/completions` paths itself.

Gateway operations endpoints:

```bash
curl http://localhost:8080/lsdf/health
curl http://localhost:8080/lsdf/metrics
curl "http://localhost:8080/lsdf/metrics?format=json"
```

For shared environments, set `LSDF_MANAGEMENT_TOKEN` so `/lsdf/health` and `/lsdf/metrics` require a bearer token or `X-LSDF-Management-Token`. Set `LSDF_MANAGEMENT_ENABLED=false` to disable `/lsdf/*` entirely while leaving `/v1/*` unchanged.

## Provider Playbooks

Use presets to generate gateway env files:

```bash
docker compose run --rm cli init --upstream litellm --output .lsdf.env --force
docker compose run --rm cli init --upstream openrouter --output .lsdf.env --force
docker compose --env-file .lsdf.env up gateway
```

Recommended LiteLLM topology is `app -> LSDF gateway -> LiteLLM Proxy -> provider fleet`. OpenRouter is configured as an upstream at `https://openrouter.ai/api/v1`, while application clients still point at `http://localhost:8080/v1`. See `docs/provider-playbook.md` and `docs/integration-recipes.md`.

## Reversible Token Vault

Irreversible tokens remain the default. For reversible local tokenization, generate a key and run the gateway with vault mode:

```bash
docker compose run --rm cli vault keygen
```

Set `LSDF_TOKENIZATION_MODE=vault`, `LSDF_VAULT_PATH=/workspace/.lsdf/vault.sqlite`, and `LSDF_VAULT_KEY` in your environment. Vault values are encrypted at rest; audit, metrics, reports, and summaries never print plaintext. Resolving a token requires the Docker Compose vault command with `--reveal-sensitive-value`.

Operational helpers (set the key variables securely in the invoking shell; `run -e` forwards them without placing keys in command arguments):

```bash
docker compose run --rm cli vault backup --vault-path .lsdf/vault.sqlite --output .lsdf/vault.backup.sqlite
docker compose run --rm -e LSDF_OLD_VAULT_KEY -e LSDF_NEW_VAULT_KEY cli vault rotate-key --vault-path .lsdf/vault.sqlite --old-key-env LSDF_OLD_VAULT_KEY --new-key-env LSDF_NEW_VAULT_KEY --output .lsdf/vault.rotated.sqlite
docker compose run --rm -e LSDF_VAULT_KEY cli vault resolve TOKEN --vault-path .lsdf/vault.sqlite --reveal-sensitive-value
```

## Policy Signing

Use Ed25519 signatures for custom policy governance:

```bash
mkdir -p .lsdf/policies
cp policies/default.yaml .lsdf/policies/default.yaml
docker compose run --rm cli policy keygen --public-key .lsdf/policy.pub --private-key .lsdf/policy.key
docker compose run --rm cli policy sign .lsdf/policies/default.yaml --private-key .lsdf/policy.key --output .lsdf/policies/default.yaml.sig
docker compose run --rm cli policy verify .lsdf/policies/default.yaml --signature .lsdf/policies/default.yaml.sig --public-key .lsdf/policy.pub
```

The gateway requires the signature beside the custom policy as `<policy>.sig`. Mount the policy, signature, and trusted public key read-only, then set `LSDF_POLICY`, `LSDF_REQUIRE_POLICY_SIGNATURE=true`, and `LSDF_POLICY_PUBLIC_KEY` to their container paths. See the complete [source and release deployment override](docs/security-model.md#signed-policy-deployment). Keep the private signing key with the signer.

## Policy Profiles

| Profile | Use When | Behavior |
| --- | --- | --- |
| `dev` | Local prototyping | Lower-friction testing with visible findings. |
| `monitor` | Measuring impact | Logs decisions without enforcing transforms or blocks. |
| `default` | Starting enforcement | Blocks inbound secrets, redacts output secrets/identifiers, blocks risky dispatch surfaces. |
| `strict` | High-risk workflows | More aggressive blocking on reasoning, traces, and sensitive surfaces. |
| `broad-pii` | Broad local PII/PHI checks | Adds contextual-broad and GLiNER to the dependency-light baseline. |
| `broad-pii-ml` | Optional ML-backed privacy checks | Adds OpenAI privacy-filter to `broad-pii`. |
| `healthcare` | PHI-oriented workflows | Healthcare ruleset for PHI/MRN handling; also available as a domain pack. |

Domain packs can be layered onto posture profiles:

| Pack | Adds |
| --- | --- |
| `healthcare` | Stricter PHI/MRN dispatch and outbound identity handling. |
| `financial` | Payment/account/tax-adjacent rules for financial workflows. |
| `enterprise-dlp` | Stronger secret/confidential dispatch and output handling. |

## FAQ

### Why is EMAIL not redacted in `default`?

`default` is the low-friction local-agent profile: it blocks secrets and hard identifiers, but generic contact and identity shapes are handled conservatively so ordinary support text and developer logs do not get over-redacted. Use `balanced`, `broad-pii`, or `broad-pii-ml` when broad generic PII redaction is the goal.

## Proof And Limits

LSDF includes a safe eval harness and proof report:

```bash
docker compose run --rm cli eval evals/safety_matrix.json --format markdown
docker compose run --rm cli compare-detectors evals/safety_matrix.json --format markdown
docker compose run --rm cli protection-report --format markdown
docker compose run --rm cli eval-report --profile default --profile balanced --format markdown > .lsdf/eval-current.md
docker compose run --rm cli proof-bundle --output .lsdf/proof --format markdown
```

`EVAL.md` records per-detector-family threat findings versus benign findings, plus latency, for the dependency-light and optional ML profiles. Its dated snapshot includes historical external benchmark rows and aggregates. Current default regeneration uses four bundled threat corpora; external benchmark results require an explicitly supplied, appropriately licensed local dataset.

Reports redact raw sensitive values by default, preserve known-gap counts, and include detector provenance. The dependency-light default uses regex, entropy, medical-pattern, and contextual-anchored detectors. Presidio and OpenAI privacy-filter adapters are optional and remain outside the default runtime path.

LSDF is not a compliance certification, SIEM, endpoint monitor, jailbreak product, or promise of perfect detection. It is a practical runtime firewall and proof system for sensitive-data exposure in LLM apps.

The built-in `medical-regex` detector is lightweight pattern matching for common clinical strings such as selected lab values, ICD-like codes, and medication-dosage patterns. It is not full HIPAA de-identification; healthcare deployments should validate against domain data and add dedicated medical NER or review workflows.

## More Docs

- [EVAL.md](EVAL.md): dated per-detector signal-vs-noise snapshot. Use the commands above for fresh dependency-light reports; optional-profile results require prepared models.
- [Performance](docs/performance.md): dated per-profile latency measurements. Save new measurements under `.lsdf/`.
- `docs/container-workflow.md`: Docker-only workflow.
- `docs/detector-composition.md`: how to choose detector families and profiles using measured recall, latency, and FP cells.
- `docs/measured-protection.md`: scoped public evidence for the optional ML path.
- `docs/detector-adapter-contract.md`: how ML detectors normalize findings, plus the current library/test extension point for custom detectors.
- `docs/integration-recipes.md`: copy-paste client and sanitizer recipes.
- `docs/production-operations.md`: health, metrics, audit export, and vault operations.
- `docs/security-model.md`: threat model, encrypted vault, policy signatures, and disclosure.
- `docs/provider-playbook.md`: OpenAI-compatible provider setup.
- `docs/policy-cookbook.md`: rollout and policy authoring recipes.
- `docs/operational-rollout-guide.md`: adoption and operations rollout.
