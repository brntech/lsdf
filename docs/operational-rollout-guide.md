# Operational Rollout Guide

Updated: 2026-09-08

Use this guide for a pilot that starts safe and gets stricter with evidence.

Complete [Installation](installation.md) first. These commands use the source checkout's `gateway` and `cli` services, which share `.lsdf/` through the checkout mount. Start your LiteLLM upstream separately and supply `LSDF_UPSTREAM_API_KEY` when it requires authentication. Published runtime containers use separate persistent storage; see [Production Operations](production-operations.md).

## 1. Start In Monitor Mode

```bash
docker compose run --rm cli init --upstream litellm --profile monitor \
  --audit-jsonl-path /workspace/.lsdf/audit.jsonl \
  --metrics-jsonl-path /workspace/.lsdf/metrics.jsonl \
  --output .lsdf.env --force
docker compose --env-file .lsdf.env up -d gateway
```

Send representative application traffic through `http://localhost:8080/v1`, then review audit summaries and metrics. `init` does not create traffic or telemetry files. Monitor mode observes findings but does not sanitize or block ordinary matched traffic.

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

Keep the gateway behind ingress authentication and TLS for shared access; the gateway does not authenticate client chat requests. Set `LSDF_MANAGEMENT_TOKEN` to protect `/lsdf/*`, or keep management enabled only behind a trusted reverse proxy. Setting `LSDF_MANAGEMENT_ENABLED=false` removes these endpoints entirely, including from the proxy. It does not protect `/v1/chat/completions`.

Use authenticated requests to check protected management endpoints. The built-in `smoke` and `quickstart-report` commands do not send management tokens; their management checks are intended for the unprotected local setup.

## 4. Move To Enforcement

Switch to `default`, then add domain packs where the application has representative fixtures. Keep the same upstream and telemetry settings. The example below replaces `.lsdf.env`; retain any additional local settings before running it, and check that shell `LSDF_PROFILE` or `LSDF_POLICY` values do not override the file.

```bash
docker compose run --rm cli init --upstream litellm --profile default --domain-pack enterprise-dlp \
  --audit-jsonl-path /workspace/.lsdf/audit.jsonl \
  --metrics-jsonl-path /workspace/.lsdf/metrics.jsonl \
  --output .lsdf.env --force
docker compose --env-file .lsdf.env up -d --force-recreate gateway
```

## 5. Vault Operations

Use irreversible tokenization unless reversible resolution is required. When vault mode is enabled, back up before rotation and write rotated vaults to a new file.

Set `LSDF_OLD_VAULT_KEY` and `LSDF_NEW_VAULT_KEY` in your shell through your secret-management process, then explicitly pass them into the CLI container:

```bash
docker compose run --rm cli vault backup --vault-path .lsdf/vault.sqlite --output .lsdf/vault.backup.sqlite
docker compose run --rm -e LSDF_OLD_VAULT_KEY -e LSDF_NEW_VAULT_KEY cli vault rotate-key --vault-path .lsdf/vault.sqlite --old-key-env LSDF_OLD_VAULT_KEY --new-key-env LSDF_NEW_VAULT_KEY --output .lsdf/vault.rotated.sqlite
```

## 6. Incident Response

- Preserve raw-value-safe audit and metrics JSONL.
- Export audit events with `audit-export`.
- Generate a proof bundle and security report.
- Do not reveal vault plaintext unless an authorized operator runs `vault resolve --reveal-sensitive-value`.
