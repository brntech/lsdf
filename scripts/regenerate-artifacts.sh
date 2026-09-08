#!/usr/bin/env bash
# Refresh current reports under ignored .lsdf/current-reports/.
# Recorded EVAL.md, docs/performance.md, comparison and dated sweep
# snapshots are preserved. Foundation recall keeps its canonical writer.
#
# Always: default/balanced latency and evaluation; foundation recall/history.
# With a ready optional model cache: separate full-matrix latency/evaluation,
# comparator and a dated threshold sweep. No models are downloaded implicitly.
#
# Usage: bash scripts/regenerate-artifacts.sh
set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")"/.. && pwd)"
cd "${REPO_ROOT}"
COMMIT_SHA="$(GIT_DISCOVERY_ACROSS_FILESYSTEM=1 git rev-parse --short=12 HEAD 2>/dev/null || printf 'unknown')"

REPORT_DIR=".lsdf/current-reports"
PERF_DEFAULT_OUT="${REPORT_DIR}/performance-default-balanced.md"
PERF_FULL_OUT="${REPORT_DIR}/performance-full-matrix.md"
EVAL_DEFAULT_OUT="${REPORT_DIR}/eval-default-balanced.md"
EVAL_OUT="${REPORT_DIR}/eval-full-matrix.md"
COMPARISON_OUT="${REPORT_DIR}/comparative-protection.md"
SWEEP_OUT="${REPORT_DIR}/fp-lever-sweep-$(date +%Y-%m-%d).md"
SYSTEM_RECALL_OUT="docs/system-recall.md"
mkdir -p "${REPORT_DIR}"

# Override operator download opt-ins for every optional invocation in this script.
OPTIONAL_RUN=(docker compose --profile optional run --rm
    -e LSDF_GLINER_LOCAL_FILES_ONLY=true
    -e LSDF_OPENAI_PRIVACY_FILTER_LOCAL_FILES_ONLY=true)

# Use a temporary sibling so a successful rename stays on the same filesystem.
# Failed or empty output leaves the preceding report intact.
write_atomic() {
    local out="$1"
    local tmp
    tmp="$(mktemp "${out}.tmp.XXXXXX")"
    if "${@:2}" > "${tmp}" && [[ -s "${tmp}" ]]; then
        mv "${tmp}" "${out}"
        echo "[regen] wrote $(wc -l < "${out}") lines to ${out}"
    else
        local rc=$?
        rm -f "${tmp}"
        echo "[regen] ERROR: regeneration of ${out} failed (rc=${rc}); existing file unchanged" >&2
        return "${rc}"
    fi
}

echo "[regen] regenerating ${PERF_DEFAULT_OUT} via cli latency-table"
write_atomic "${PERF_DEFAULT_OUT}" \
    docker compose run --rm cli latency-table \
        --profile default --profile balanced --iterations 50 --format markdown

echo "[regen] regenerating ${EVAL_DEFAULT_OUT} via cli eval-report"
write_atomic "${EVAL_DEFAULT_OUT}" \
    docker compose run --rm cli eval-report \
        --profile default --profile balanced --format markdown

# Synthetic fixtures/fake optional providers need no model cache.
# The recall command owns its canonical report and history writes.
echo "[regen] regenerating ${SYSTEM_RECALL_OUT} via cli detectors recall --regenerate"
docker compose run --rm -e LSDF_COMMIT_SHA="${COMMIT_SHA}" cli detectors recall \
    --regenerate --output "${SYSTEM_RECALL_OUT}" >/dev/null
echo "[regen] wrote $(wc -l < "${SYSTEM_RECALL_OUT}") lines to ${SYSTEM_RECALL_OUT}"

echo "[regen] probing optional model cache via doctor --profile broad-pii-ml"
DOCTOR_OUT="${REPORT_DIR}/doctor-optional.json"
DOCTOR_TMP="$(mktemp "${DOCTOR_OUT}.tmp.XXXXXX")"
DOCTOR_RC=0
if "${OPTIONAL_RUN[@]}" optional-cli \
    doctor --profile broad-pii-ml --format json > "${DOCTOR_TMP}"; then
    DOCTOR_RC=0
else
    DOCTOR_RC=$?
fi

# A valid fresh failure report is useful diagnostics. Publish it too, but never
# replace the preceding probe with empty/partial startup output or use a stale
# successful probe to authorize this run's full matrix.
if PROBE_STATE="$(docker compose run --rm -T python -c '
import json
import sys

try:
    report = json.load(sys.stdin)
except ValueError:
    print("[regen] doctor did not return valid JSON", file=sys.stderr)
    sys.exit(1)
if not isinstance(report, dict) or report.get("status") not in ("ok", "error") or not isinstance(report.get("checks"), list):
    print("[regen] doctor did not return a valid probe object", file=sys.stderr)
    sys.exit(1)
checks = report["checks"]
required = ("gliner", "openai_privacy_filter")
ready = report["status"] == "ok" and any(
    isinstance(check, dict) and check.get("name") == "detectors"
    and check.get("status") == "ok" and isinstance(check.get("families"), list)
    and all(family in check["families"] for family in required)
    for check in checks
)
if not ready:
    print("[regen] full matrix requires loaded gliner and openai_privacy_filter", file=sys.stderr)
print("ready" if ready else "not-ready")
' < "${DOCTOR_TMP}")" && [[ "${PROBE_STATE}" == ready || "${PROBE_STATE}" == not-ready ]]; then
    mv "${DOCTOR_TMP}" "${DOCTOR_OUT}"
else
    rm -f "${DOCTOR_TMP}"
    PROBE_STATE=unavailable
    echo "[regen] WARNING: no valid fresh doctor JSON; previous probe, if present, is unchanged." >&2
fi

if [[ ${DOCTOR_RC} -eq 0 && "${PROBE_STATE}" == ready ]]; then
    echo "[regen] both optional model families are ready in cache-only mode"
else
    echo "[regen] WARNING: full optional ML matrix is not ready (doctor exit ${DOCTOR_RC}; probe ${PROBE_STATE})." >&2
    echo "[regen]   Skipping ${PERF_FULL_OUT}, ${EVAL_OUT}, ${COMPARISON_OUT}, and ${SWEEP_OUT}." >&2
    echo "[regen]   Existing optional reports and all recorded snapshots are unchanged." >&2
    if [[ "${PROBE_STATE}" == unavailable ]]; then
        echo "[regen]   Any retained probe is stale for this run; inspect the startup/validation errors above and retry." >&2
    else
        echo "[regen]   Fresh diagnostics saved to ${DOCTOR_OUT}; see docs/measured-protection.md for cache readiness." >&2
    fi
    exit 0
fi

# n=1 is an explicitly labeled individual payload sample; streaming keeps
# its actual repeated chunk sample counts. Never replace the 50-iteration
# default/balanced report with this separate, more expensive profile matrix.
echo "[regen] regenerating ${PERF_FULL_OUT} via optional-cli latency-table"
write_atomic "${PERF_FULL_OUT}" \
    "${OPTIONAL_RUN[@]}" optional-cli latency-table \
        --profile default --profile balanced \
        --profile broad-pii --profile broad-pii-ml \
        --iterations 1 --format markdown

echo "[regen] regenerating ${EVAL_OUT} via optional-cli eval-report"
write_atomic "${EVAL_OUT}" \
    "${OPTIONAL_RUN[@]}" optional-cli eval-report \
        --profile default --profile balanced \
        --profile broad-pii --profile broad-pii-ml --format markdown

echo "[regen] regenerating ${COMPARISON_OUT} via build_comparative_protection.py"
write_atomic "${COMPARISON_OUT}" \
    "${OPTIONAL_RUN[@]}" --entrypoint python optional-cli \
        scripts/build_comparative_protection.py --output - --seed 0

echo "[regen] regenerating ${SWEEP_OUT} via optional-cli fp-lever-table"
if ! write_atomic "${SWEEP_OUT}" \
    "${OPTIONAL_RUN[@]}" optional-cli fp-lever-table \
        --threshold 0.50 --threshold 0.70 --threshold 0.85 --threshold 0.95 \
        --format markdown; then
    echo "[regen] WARNING: OpenAI privacy-filter threshold sweep is unavailable." >&2
    echo "[regen]   ${EVAL_OUT} was refreshed; ${SWEEP_OUT} was left unchanged." >&2
fi

echo "[regen] done; recorded snapshots are unchanged"
