#!/usr/bin/env bash
# scripts/regenerate-artifacts.sh — refresh all committed reproducibility
# artifacts from the public corpora in one shot.
#
# Always regenerates (no model cache needed):
#   - docs/performance.md      — cli latency-table, default profile
#   - docs/system-recall.md    — cli detectors recall --regenerate
#
# Regenerated only when the optional ML profile's model cache is
# available (doctor --profile broad-pii-ml exits 0):
#   - EVAL.md                                    — cli eval-report,
#                                                  default + balanced
#                                                  + broad-pii + broad-pii-ml
#   - docs/comparative-protection.md             — comparator artifact
#   - docs/fp-lever-sweep-$(date +%Y-%m-%d).md   — cli fp-lever-table
#
# Why dated sweep file: existing committed sweep docs are historical
# snapshots — re-running this script preserves them and adds a new
# dated file, leaving operator narrative (recall caveats etc.) intact.
#
# If the optional model cache is missing, the script prints a warning,
# skips the optional artifacts, and exits 0 — operators on default-only
# environments still benefit from the latency-table refresh.
#
# Usage:
#   bash scripts/regenerate-artifacts.sh

set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")"/.. && pwd)"
cd "${REPO_ROOT}"
COMMIT_SHA="$(GIT_DISCOVERY_ACROSS_FILESYSTEM=1 git rev-parse --short=12 HEAD 2>/dev/null || printf 'unknown')"

PERF_OUT="docs/performance.md"
SYSTEM_RECALL_OUT="docs/system-recall.md"
EVAL_OUT="EVAL.md"
COMPARISON_OUT="docs/comparative-protection.md"
SWEEP_OUT="docs/fp-lever-sweep-$(date +%Y-%m-%d).md"

# Helper: write CLI output atomically. Direct `> file` truncates the
# destination before the command runs, so a mid-stream failure (container
# crash, OOM kill) leaves the committed artifact corrupted. We instead
# render to a temp file and `mv` on success.
write_atomic() {
    local out="$1"
    local tmp
    tmp="$(mktemp)"
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

# 1. Always: regenerate the dependency-light latency table. Pure-Python
#    detectors run on any host without a model cache. When the optional
#    profile is reachable, step 3 overwrites this with the full measured table.
echo "[regen] regenerating ${PERF_OUT} via cli latency-table"
write_atomic "${PERF_OUT}" \
    docker compose run --rm cli latency-table --format markdown

# 2. Always: regenerate the foundation-layer detector recall artifact. This
#    uses synthetic fixtures and fake providers for optional detector adapters,
#    so it does not require a model cache.
echo "[regen] regenerating ${SYSTEM_RECALL_OUT} via cli detectors recall --regenerate"
docker compose run --rm -e LSDF_COMMIT_SHA="${COMMIT_SHA}" cli detectors recall \
    --regenerate --output "${SYSTEM_RECALL_OUT}" >/dev/null
echo "[regen] wrote $(wc -l < "${SYSTEM_RECALL_OUT}") lines to ${SYSTEM_RECALL_OUT}"

# 3. Probe the optional ML profile via doctor. The doctor CLI is
#    intentionally local-files-only — it reports the privacy-filter
#    detector as unavailable instead of downloading the model
#    implicitly, and exits nonzero when unavailable.
echo "[regen] probing optional ML profile model cache via doctor --profile broad-pii-ml"
set +e
docker compose --profile optional run --rm optional-cli \
    doctor --profile broad-pii-ml --format json >/dev/null 2>&1
DOCTOR_RC=$?
set -e

if [[ ${DOCTOR_RC} -ne 0 ]]; then
    echo "[regen] WARNING: optional ML profile is not reachable (doctor exit ${DOCTOR_RC})." >&2
    echo "[regen]   Skipping ${EVAL_OUT}, ${COMPARISON_OUT}, and fp-lever-sweep regeneration." >&2
    echo "[regen]   See docs/measured-protection.md for how to populate the model cache." >&2
    exit 0
fi

# 4. Optional path is reachable — regenerate EVAL.md and a fresh
#    dated fp-lever sweep.
echo "[regen] regenerating ${PERF_OUT} via optional-cli latency-table"
write_atomic "${PERF_OUT}" \
    docker compose --profile optional run --rm optional-cli latency-table \
        --profile default --profile balanced \
        --profile broad-pii --profile broad-pii-ml \
        --iterations 1 --format markdown

echo "[regen] regenerating ${EVAL_OUT} via cli eval-report"
write_atomic "${EVAL_OUT}" \
    docker compose --profile optional run --rm optional-cli eval-report \
        --profile default --profile balanced \
        --profile broad-pii --profile broad-pii-ml --format markdown

echo "[regen] regenerating ${COMPARISON_OUT} via build_comparative_protection.py"
write_atomic "${COMPARISON_OUT}" \
    docker compose --profile optional run --rm --entrypoint python optional-cli \
        scripts/build_comparative_protection.py --output - --seed 0

echo "[regen] regenerating ${SWEEP_OUT} via cli fp-lever-table"
if ! write_atomic "${SWEEP_OUT}" \
    docker compose --profile optional run --rm optional-cli fp-lever-table \
        --threshold 0.50 --threshold 0.70 --threshold 0.85 --threshold 0.95 \
        --format markdown; then
    echo "[regen] WARNING: OpenAI privacy-filter threshold sweep is unavailable." >&2
    echo "[regen]   ${EVAL_OUT} was refreshed; ${SWEEP_OUT} was left unchanged." >&2
fi

echo "[regen] done"
