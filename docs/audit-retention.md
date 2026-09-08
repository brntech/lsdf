# Audit Retention, Rotation, and Purge

LSDF's gateway emits raw-value-safe JSONL audit events through the bundled
`JsonlAuditSink` (see `src/lsdf/audit.py`). The audit log is the
authoritative trail for "what did the firewall do, and why?" — it must
survive routine operations without losing append integrity, but it also
needs a deletion story for storage caps, retention windows, and GDPR-style
right-to-erasure requests.

This doc covers the three layers operators need to plan: rotation,
retention, and per-event purge. Each layer is intentionally small enough
to fit a one-paragraph operational runbook.

## 1. Rotation (already shipped)

`JsonlAuditSink` rotates by bytes. When the live `audit.jsonl` reaches
`rotate_bytes`, it shifts to `audit.jsonl.1` and the rotation chain
cascades up to `rotate_backups` files (default 3). The live file is
recreated empty for the next event.

```python
from lsdf.audit import JsonlAuditSink

sink = JsonlAuditSink(
    "/workspace/.lsdf/audit.jsonl",
    rotate_bytes=64 * 1024 * 1024,   # 64 MB per file
    rotate_backups=10,               # keep .1 through .10
)
```

The bundled `cli` Compose service mounts the repo root as `/workspace`,
so any path under `/workspace/.lsdf/` is host-visible at the same
relative path. The bundled `demo-gateway` service writes to
`/workspace/.lsdf/demo/audit.jsonl` by default. Production deployments
that mount a dedicated audit volume (e.g. `-v /var/lib/lsdf:/var/lib/lsdf`)
should align both the gateway's `LSDF_AUDIT_JSONL_PATH` and the
`audit-purge` argument with the in-container path of that mount —
otherwise the sweep silently no-ops because the parent directory does
not exist inside the container.

Properties of the rotated set:

- The live file is `audit.jsonl`. It is the append target for the gateway.
- Rotated backups are `audit.jsonl.1`, `audit.jsonl.2`, ..., up to
  `audit.jsonl.<rotate_backups>`. Lower index = newer.
- Rotation never reads the live file — so size-based rotation is
  raw-value-safe by construction.
- Gateway audit append failures fail open with raw-value-safe stderr warnings.

## 2. Retention windows

Rotation alone caps total storage but does not enforce *time-based*
retention. The bundled `cli audit-purge` subcommand fills that gap.

```bash
docker compose run --rm cli audit-purge \
    /workspace/.lsdf/audit.jsonl \
    --older-than-days 30 \
    --dry-run
```

Behavior:

- Operates on rotated backups only (`<path>.<int>`). The live audit file
  is never touched, even if its mtime is older than the cutoff. Append-
  only audit semantics depend on the live file surviving sweeps.
- Time comparison uses each rotated file's mtime against
  `now() - older_than_days`.
- Errors on individual files (permission denied, missing inode) are
  collected in the JSON report's `errors` list rather than aborting the
  sweep — one bad file does not block deletion of the rest.
- Exit code: `0` when no errors, `1` when any per-file error was
  collected, `2` for argument errors (e.g. negative `--older-than-days`,
  or `--older-than-days 0` — see below).
- `--dry-run` classifies files without deleting; useful for validating a
  retention policy before scheduling it.
- The CLI requires `--older-than-days >= 1`. A `0` window would purge
  every rotated backup, which is rarely the intended outcome and can
  happen accidentally if a cron environment variable expands to empty.
  Programmatic callers that genuinely want a 0-day sweep can use
  `lsdf.audit.purge_rotated_audit_files(...)` directly — that path
  preserves the `>= 0` semantics for testing and operator scripting.

Recommended cron pattern (operator-side, outside the LSDF container):

```bash
# /etc/cron.daily/lsdf-audit-retention
docker compose -f /opt/lsdf/docker-compose.yml run --rm cli audit-purge \
    /workspace/.lsdf/audit.jsonl \
    --older-than-days 90 \
    >> /var/log/lsdf/retention.log 2>&1
```

(Replace the in-container path with whatever your gateway's
`LSDF_AUDIT_JSONL_PATH` resolves to inside the container, after any
production volume mount.)

For weekly retention sweeps with longer windows, schedule daily so a
missed cron run only delays a sweep by one day rather than seven.

## 3. S3 archive flow

LSDF deliberately ships no S3 client — boto3 is heavy, and operators
running in the cloud already have credentials and tooling on the host.
The archive flow is therefore "rotate locally, sync rotated files
upstream, purge once synced." Operator-side composition with `rclone`
covers AWS S3, Cloudflare R2, GCS, Azure Blob, and most other object
stores without LSDF needing a per-provider adapter.

```bash
# Sync rotated audit files to S3 (skips the live file; rotated files are
# immutable once created so --copy-links is safe). Run on the host —
# rclone is not bundled in the cli container.
rclone copy --include 'audit.jsonl.*' \
    "$LSDF_HOST_AUDIT_DIR" \
    s3:my-lsdf-audit-bucket/$(hostname)/$(date +%Y-%m)/

# Then purge locally inside the cli container.
docker compose run --rm cli audit-purge \
    /workspace/.lsdf/audit.jsonl \
    --older-than-days 30
```

The `audit.jsonl.*` glob requires a literal dot after the live name, so
the live append target (`audit.jsonl`, no suffix) is excluded — only
rotated backups are uploaded.

The archived files retain their LSDF rotation suffix (`.jsonl.1` etc.),
which is `kept by the operator` semantic noise rather than meaningful in
the archive. If a long-term-archive process re-numbers files for
chronological ordering, do that re-numbering on the archive side; do not
rename rotated files in place under LSDF's control.

The `audit-export` CLI subcommand (`docker compose run --rm cli
audit-export`) re-emits the JSONL in target-vendor shape (Splunk HEC,
Elastic ECS, Datadog, generic) and is the right path for *real-time*
forwarding into a SIEM. Use it for the live trail; use S3 for the
cold-archive of rotated files.

## 4. GDPR-style per-event purge

LSDF's audit events are raw-value-safe by design — they carry redacted
findings, decision metadata, surface labels, and detector identifiers,
but never the matched span text. So a typical "right to erasure" request
does not actually require touching the audit log: the underlying value
that triggered the audit was never written.

That said, three per-event purge scenarios remain:

1. **Operator added optional metadata** (e.g. a request_id that
   correlates with an upstream user_id table). If the metadata itself is
   subject to erasure, the audit event needs scrubbing.
2. **A finding's metadata or pointer accidentally encodes user identity**
   (e.g. a tool-call argument's JSON-pointer path including a user-named
   resource).
3. **Compliance regime requires log-side erasure** independent of
   raw-value safety, as a defense-in-depth posture.

For all three, the recommended approach is **tombstoning**, not hard
deletion. Tombstoning replaces the affected JSONL line with a marker
event preserving the original timestamp:

```python
import json
from datetime import datetime, timezone
from pathlib import Path

def tombstone_event(path: Path, *, predicate) -> int:
    """Replace each line where `predicate(event)` is True with a tombstone.

    Returns the number of tombstoned lines. Operates on a single audit
    file (live or rotated) — call once per file you want to scrub, after
    rotation has placed the target line in a rotated backup so the live
    append stream is undisturbed.
    """
    rewrites = 0
    out_lines = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            out_lines.append(line)
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            out_lines.append(line)
            continue
        if predicate(event):
            tombstone = {
                "timestamp": event.get("timestamp")
                or datetime.now(timezone.utc).isoformat(),
                "tombstoned": True,
                "decision_count": 0,
                "blocked": False,
                "decisions": [],
            }
            out_lines.append(json.dumps(tombstone, separators=(",", ":")))
            rewrites += 1
        else:
            out_lines.append(line)
    path.write_text("\n".join(out_lines) + "\n", encoding="utf-8")
    return rewrites
```

Hard deletion (removing the line entirely) breaks any byte-offset-based
indexing a downstream tool may have. Tombstoning keeps the JSONL line
count stable while removing the offending payload, and the marker shape
(`tombstoned: true`) is parseable by `audit-summary` and `audit-export`
without special handling.

LSDF intentionally does not ship a built-in tombstone CLI. The operator
side knows which event-id schema correlates with their user records;
LSDF cannot infer it. The recipe above is small enough to drop into a
maintenance script alongside the operator's existing
data-subject-erasure tooling.

## 5. Compliance considerations

- **Append-only contract.** Routine retention sweeps and tombstoning
  must not modify the live `audit.jsonl` while the gateway is appending.
  Run sweeps after a forced rotation (e.g. send `SIGHUP` to a wrapping
  process if your deployment supports it, or schedule sweeps during
  low-traffic windows). The bundled `audit-purge` operates on rotated
  files only and is safe to run concurrently with appends.
- **Raw-value safety on archived files.** Files written by
  `JsonlAuditSink` are raw-value-safe by construction (the value never
  reaches the sink). Archive transports should preserve that property —
  do not let an intermediate enrichment step add raw value text to an
  archived JSONL line.
- **Retention-window selection.** A common starting point is 90 days for
  hot retention (rotate + on-disk) plus 1-3 years cold archive in S3 or
  equivalent. Adjust per regulatory regime (HIPAA, GDPR, PCI-DSS).
- **Testing the retention pipeline.** Use `--dry-run` first when
  introducing a new retention policy to a live deployment. The dry-run
  report shows exactly which files would be deleted under the proposed
  policy without touching them.

## 6. Reference: file-shape contract

| File | Role | Touched by `audit-purge`? | Touched by tombstone recipe? |
|---|---|---|---|
| `audit.jsonl` | Live append target | No, ever | Yes, only after rotation moves the target line out |
| `audit.jsonl.<N>` | Rotated backup, lower N = newer | Yes, when older than cutoff | Yes |
| `audit.jsonl.bak`, other suffixes | Operator-managed; not LSDF's | No | No (operator owns these) |

Anything outside the `<live name>.<int>` shape is operator-managed and
out of scope for `audit-purge`. The retention sweep deliberately
ignores arbitrary suffixes so an operator-side archive workflow can
co-exist on the same directory without LSDF deleting non-LSDF files.

## Writer coordination

Rotation and append are serialized within one shared sink instance. Use a single writer process per path. Coordinate separate sink instances, other processes, and manual rotation or purge; the in-process lock does not cover them. Retention recognizes nonempty ASCII decimal suffixes, including `.0` and `.001`; reserve that filename shape for audit backups.
