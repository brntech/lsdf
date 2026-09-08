# Security Model

Date: 2026-04-29

LSDF is a runtime sensitive-data firewall and proof system. It is not a compliance certification, endpoint monitor, SIEM, or guarantee of perfect detection.

## Distribution Boundary

The standard runtime image starts the lightweight gateway and excludes external benchmark corpora and optional ML dependencies. Policy-validation fixtures and first-party proof matrices are intentional runtime assets. Source evaluation accepts operator-supplied licensed data, but generated or external data under `.lsdf/` is excluded from image builds. Existing vault, policy-signing, audit, and detector-adapter code remain open-source; no paid entitlement is required for those features. Consult `THIRD_PARTY_NOTICES.md` for third-party software, model, and data terms.

## Protected Surfaces

LSDF scans request messages, system/developer/tool-result inputs, RAG context, model responses, streaming content, reasoning fields, streamed tool-call arguments, and observability trace/log payloads.

## Raw-Value Safety

Audit events, metrics, reports, demos, explanations, protection reports, and SIEM exports omit raw sensitive values. Evidence is non-reversible unless the encrypted vault is explicitly enabled and resolved through the vault CLI.

## Detector Posture

The default runtime stays dependency-light with regex, entropy, and lightweight medical-pattern detectors. `balanced` adds dependency-light generic output redaction. `broad-pii` is the release-gated local posture: regex, entropy, medical-regex, contextual PII, GLiNER, inbound generic identity/PHI redaction, and broad-pii output surface containment when contextual evidence appears. `broad-pii-ml` uses the same local broad-pii stack and adds OpenAI privacy-filter only when that reference model is loadable. Custom detectors use the same adapter contract and must preserve raw-value-safe reporting.

The built-in `medical-regex` detector is not full HIPAA de-identification. It is a small pattern scanner for selected clinical strings; regulated healthcare deployments should add dedicated medical NER, domain fixtures, and compliance review.

## Vault

Reversible tokenization requires `cryptography` and an encrypted SQLite vault. LSDF stores encrypted plaintext plus safe metadata. Tokens are deterministic for the same entity/value/key pair and use the shape `lsdf_tok_<entity>_<id>`.

Vault operations are local-first:

```bash
docker compose run --rm cli vault check --vault-path .lsdf/vault.sqlite
docker compose run --rm cli vault backup --vault-path .lsdf/vault.sqlite --output .lsdf/vault.backup.sqlite
docker compose run --rm cli vault rotate-key --vault-path .lsdf/vault.sqlite --old-key-env LSDF_OLD_VAULT_KEY --new-key-env LSDF_NEW_VAULT_KEY --output .lsdf/vault.rotated.sqlite
```

Rotation writes a new vault file and leaves the source untouched. External KMS/HSM adapters are not implemented.

## Policy Governance

Use:

```bash
docker compose run --rm cli policy validate policies/default.yaml
docker compose run --rm cli policy diff policies/default.yaml policies/strict.yaml
docker compose run --rm cli policy keygen --public-key .lsdf/policy.pub --private-key .lsdf/policy.key
docker compose run --rm cli policy sign policies/default.yaml --private-key .lsdf/policy.key --output .lsdf/default.yaml.sig
docker compose run --rm cli policy verify policies/default.yaml --signature .lsdf/default.yaml.sig --public-key .lsdf/policy.pub
```

New signatures use Ed25519. Legacy hash sidecars are still readable as migration artifacts and are marked `legacy` in verification output. `LSDF_REQUIRE_POLICY_SIGNATURE=true` makes the gateway reject unsigned or invalid custom policy files; set `LSDF_POLICY_PUBLIC_KEY` for Ed25519 verification. Built-in profiles and domain-pack composition remain trusted local assets.

## Management Endpoints

`/lsdf/health` and `/lsdf/metrics` expose raw-value-safe operational status. They should be bound only on trusted networks or protected by a reverse proxy. For the stdlib gateway, set `LSDF_MANAGEMENT_TOKEN` for bearer/header token checks, or set `LSDF_MANAGEMENT_ENABLED=false` to disable `/lsdf/*` without changing OpenAI-compatible `/v1/*` behavior.

## Proof Bundle

Use `docker compose run --rm cli proof-bundle --output .lsdf/proof --format markdown` to generate a raw-value-safe evaluation bundle. It is intended for review and pilot approval, not certification.

For optional ML evaluation, validate the policy with `docker compose run --rm cli policy-validate --profile broad-pii-ml`, use `doctor --profile broad-pii-ml` as a model-cache readiness check, and include the profile name in protection or proof reports.

## Disclosure

Report security issues through the repository security advisory flow. If that is unavailable, open a minimal public issue asking for a private security contact without including exploit details. Do not include raw customer data, credentials, PHI, plaintext vault contents, audit lines, prompts, traces, or proprietary logs in issues or reports.
