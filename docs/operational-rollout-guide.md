# Operational Rollout Guide

Date: 2026-04-29

Use this guide for a pilot that starts safe and gets stricter with evidence.

## 1. Start In Monitor Mode

```bash
docker compose run --rm cli init --upstream litellm --profile monitor --output .lsdf.env --force
docker compose --env-file .lsdf.env up gateway
```

Review audit summaries and metrics:

```bash
docker compose run --rm cli audit-summary .lsdf/audit.jsonl
docker compose run --rm cli metrics-summary .lsdf/metrics.jsonl --format markdown
```

## 2. Simulate Enforcement

```bash
docker compose run --rm cli simulate-policy evals/basic.json --profile default --format markdown
docker compose run --rm cli protection-report --profile default --format markdown
```

## 3. Harden Management

Set `LSDF_MANAGEMENT_TOKEN` for shared environments or set `LSDF_MANAGEMENT_ENABLED=false` and expose health/metrics through a trusted reverse proxy.

## 4. Move To Enforcement

Switch to `default`, then add domain packs where the application has representative fixtures.

```bash
docker compose run --rm cli init --upstream openrouter --profile default --domain-pack enterprise-dlp --output .lsdf.env --force
```

## 5. Vault Operations

Use irreversible tokenization unless reversible resolution is required. When vault mode is enabled, back up before rotation and write rotated vaults to a new file.

```bash
docker compose run --rm cli vault backup --vault-path .lsdf/vault.sqlite --output .lsdf/vault.backup.sqlite
docker compose run --rm cli vault rotate-key --vault-path .lsdf/vault.sqlite --old-key-env LSDF_OLD_VAULT_KEY --new-key-env LSDF_NEW_VAULT_KEY --output .lsdf/vault.rotated.sqlite
```

## 6. Incident Response

- Preserve raw-value-safe audit and metrics JSONL.
- Export audit events with `audit-export`.
- Generate a proof bundle and security report.
- Do not reveal vault plaintext unless an authorized operator runs `vault resolve --reveal-sensitive-value`.
