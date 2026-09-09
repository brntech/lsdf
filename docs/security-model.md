# Security Model

Updated: 2026-09-09

LSDF is a runtime sensitive-data firewall and proof system. It is not a compliance certification, endpoint monitor, SIEM, or guarantee of perfect detection.

## Distribution Boundary

The standard runtime image starts the lightweight gateway and excludes external benchmark corpora and optional ML dependencies. Policy-validation fixtures and first-party proof matrices are intentional runtime assets. Source evaluation accepts operator-supplied licensed data, but generated or external data under `.lsdf/` is excluded from image builds. Existing vault, policy-signing, audit, and detector-adapter code remain open-source; no paid entitlement is required for those features. Consult [Third-Party Notices](../THIRD_PARTY_NOTICES.md) for third-party software, model, and data terms, and [Installation](installation.md) for source and prebuilt-image setup.

## Protected Surfaces

LSDF scans request messages, system/developer/tool-result inputs, RAG context, model responses, streaming content, reasoning fields, streamed tool-call arguments, and observability trace/log payloads.

## Raw-Value Safety

Audit events, metrics, reports, demos, explanations, protection reports, and SIEM exports omit raw sensitive values. Evidence is non-reversible unless the encrypted vault is explicitly enabled and resolved through the vault CLI.

## Detector Posture

The default runtime stays dependency-light with regex, entropy, lightweight medical-pattern detectors, and contextual-anchored patterns. `balanced` adds dependency-light generic output redaction. `broad-pii` is the release-gated local posture: regex, entropy, medical-regex, contextual PII, GLiNER, inbound generic identity/PHI redaction, and broad-pii output surface containment when contextual evidence appears. `broad-pii-ml` uses the same local broad-pii stack and adds OpenAI privacy-filter only when that reference model is loadable. Custom detectors use the same adapter contract and must preserve raw-value-safe reporting.

Known tool correlation IDs (`chatcmpl-tool-` followed by 16 lowercase hexadecimal characters) in valid assistant function-call ID fields and tool reply ID fields are exempt from the supplementary entropy heuristic. Other detectors still inspect these fields. The same text in messages, tool arguments, and tool results is scanned normally. This avoids blocking a tool conversation solely because its generated ID resembles a secret. This format-based exception does not authenticate an ID or prove that it contains no encoded sensitive data.

The v0.4.0 gateway inspects JSON response metadata, SSE JSON metadata, and SSE envelope values (`id:`, `event:`, `retry:`, and comments). Unknown extension key names and scalar values are inspected with static diagnostic paths that cannot disclose the original keys. Metadata uses `output.content` policy rules; root trace/log fields retain `logs.traces`. An enforcing decision that would transform or block metadata withholds the JSON response with HTTP 502 or terminates SSE with a safe error. Metadata is never rewritten or stored in the vault, and a rejected frame does not release held content. Monitor mode and per-rule `on_fail` overrides retain their documented behavior.

A root response `id` matching `^chatcmpl-[A-Za-z0-9]{8,64}$` is exempt from the entropy heuristic only when `object` is `chat.completion` or `chat.completion.chunk`, `choices` is an array, and no root `messages` field is present. Other detectors still inspect it. This is an LSDF compatibility rule, not a vendor-specified format, authentication check, or guarantee against encoded data. Nested IDs and the SSE `id:` field have no response-ID exemption.

Recognized string content/reasoning fields and JSON tool-argument values retain normal policy transforms. Tool-argument object keys are also scanned: an enforcing key decision withholds the entire payload rather than renaming an argument. Serialized argument `json_pointer` paths use ordinal key/value positions; they are diagnostic labels, not semantic JSON locators. Original value paths remain internal to transformation. Malformed or non-string response content/argument shapes use the metadata rejection path. See [streaming compatibility](streaming-compatibility.md#server-sent-events-node-deno-eventsource-api).

These metadata and argument-key controls are included in v0.4.0. They inspect the documented JSON/SSE body surfaces. Non-SSE responses must parse as JSON objects. Plain text, malformed JSON, JSON arrays/scalars, and invalid encodings are withheld with HTTP 502 `invalid_upstream_response`, including in monitor mode; this is protocol validation, not a detector decision. HTTP response headers on accepted responses and general request extension key names remain outside this added inspection boundary.

The built-in `medical-regex` detector is not full HIPAA de-identification. It is a small pattern scanner for selected clinical strings; regulated healthcare deployments should add dedicated medical NER, domain fixtures, and compliance review.

## Vault

Reversible tokenization requires `cryptography` and an encrypted SQLite vault. LSDF stores encrypted plaintext plus safe metadata. Tokens are deterministic for the same entity/value/key pair and use the shape `lsdf_tok_<entity>_<id>`.

Vault operations are local-first. Before rotation, set `LSDF_OLD_VAULT_KEY` and `LSDF_NEW_VAULT_KEY` securely in the invoking shell. Pass their names through Compose with `-e`; the `cli` service does not inherit arbitrary host environment variables. Do not put key values in command arguments, committed files, or reports.

```bash
docker compose run --rm cli vault check --vault-path .lsdf/vault.sqlite
docker compose run --rm cli vault backup --vault-path .lsdf/vault.sqlite --output .lsdf/vault.backup.sqlite
docker compose run --rm -e LSDF_OLD_VAULT_KEY -e LSDF_NEW_VAULT_KEY cli vault rotate-key --vault-path .lsdf/vault.sqlite --old-key-env LSDF_OLD_VAULT_KEY --new-key-env LSDF_NEW_VAULT_KEY --output .lsdf/vault.rotated.sqlite
```

Vault backups use SQLite's online backup API, including committed WAL transactions. Choose a new output filename: existing outputs and source aliases are rejected. Keep writers coordinated during key rotation; a backup is a consistent point-in-time copy, not a continuously updated replica.

Back up the source vault before key rotation using the [vault backup commands](production-operations.md#encrypted-token-vault). Rotation writes a new vault file and leaves the source untouched. External KMS/HSM adapters are not implemented.

## Policy Governance

Use:

```bash
docker compose run --rm cli policy validate policies/default.yaml
docker compose run --rm cli policy diff policies/default.yaml policies/strict.yaml
mkdir -p .lsdf/policies
cp policies/default.yaml .lsdf/policies/default.yaml
docker compose run --rm cli policy keygen --public-key .lsdf/policy.pub --private-key .lsdf/policy.key
docker compose run --rm cli policy sign .lsdf/policies/default.yaml --private-key .lsdf/policy.key --output .lsdf/policies/default.yaml.sig
docker compose run --rm cli policy verify .lsdf/policies/default.yaml --signature .lsdf/policies/default.yaml.sig --public-key .lsdf/policy.pub
```

New signatures use Ed25519. Legacy hash sidecars remain readable for explicit CLI migration and are marked `legacy`; they cannot satisfy gateway signature enforcement or verification against a supplied public key. `LSDF_REQUIRE_POLICY_SIGNATURE=true` requires a valid Ed25519 signature for custom policy files and a trusted `LSDF_POLICY_PUBLIC_KEY`. Protect the public-key file and gateway configuration separately from writable custom policies. Built-in profiles and domain-pack composition remain trusted local assets.

## Signed policy deployment

The gateway verifies and loads the same byte snapshot, and looks for the adjacent `<policy>.sig` file. After creating the policy and signature above, save this override as `.lsdf/policy.override.yaml`. Paths below are relative to the directory containing the first Compose file:

```yaml
services:
  gateway:
    volumes:
      - ./.lsdf/policies:/opt/lsdf/policies:ro
      - ./.lsdf/policy.pub:/opt/lsdf/trust/policy.pub:ro
    environment:
      LSDF_POLICY: /opt/lsdf/policies/default.yaml
      LSDF_REQUIRE_POLICY_SIGNATURE: "true"
      LSDF_POLICY_PUBLIC_KEY: /opt/lsdf/trust/policy.pub
```

For the source gateway, retain your upstream settings in `.lsdf.env` and run:

```bash
docker compose --env-file .lsdf.env -f docker-compose.yml -f .lsdf/policy.override.yaml up -d gateway
```

For a published-image deployment, copy only the policy, its signature, and the public key into the corresponding host paths alongside the downloaded release Compose file. Use:

```bash
docker compose --env-file .lsdf.env -f compose.release.yaml -f .lsdf/policy.override.yaml up -d gateway
```

Keep the private signing key with the signer; it is not a deployment mount. The source development services mount the whole checkout, so use the published-image configuration for this narrower file boundary. Protect the trusted public key and deployment configuration from policy authors. Re-sign every policy edit and recreate the gateway to load it. For `gateway-ml` or `runtime`, use that service name in both the override and the command and include its Compose profile.

## Management Endpoints

`/lsdf/health` and `/lsdf/metrics` expose raw-value-safe operational status. They should be bound only on trusted networks or protected by a reverse proxy. For the stdlib gateway, set `LSDF_MANAGEMENT_TOKEN` for bearer/header token checks, or set `LSDF_MANAGEMENT_ENABLED=false` to disable `/lsdf/*`. The health payload reports management/client auth requirements and configured request/stream limits without token values.

Set `LSDF_CLIENT_TOKEN` independently to require bearer/header authentication on `/v1/chat/completions`. Management authentication protects only `/lsdf/*`; an upstream API key authenticates LSDF to the provider, not clients to LSDF. Keep the gateway on a trusted network or place client authentication and TLS at a reverse proxy before allowing untrusted callers. The CLI smoke and quickstart checks do not prove data-plane protection and withhold management credentials from non-local/custom gateway names.

## Proof Bundle

Use `docker compose run --rm cli proof-bundle --output .lsdf/proof --format markdown` to generate a raw-value-safe evaluation bundle. It is intended for review and pilot approval, not certification.

For optional ML evaluation, validate the policy with `docker compose run --rm cli policy-validate --profile broad-pii-ml`, use `doctor --profile broad-pii-ml` as a model-cache readiness check, and include the profile name in protection or proof reports.

## Disclosure

Report security issues through the repository security advisory flow. If that is unavailable, open a minimal public issue asking for a private security contact without including exploit details. Do not include raw customer data, credentials, PHI, plaintext vault contents, audit lines, prompts, traces, or proprietary logs in issues or reports.
