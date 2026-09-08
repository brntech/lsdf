#!/usr/bin/env bash
# scripts/record-demo.sh — record the LSDF golden demo into reproducible
# adoption-facing artifacts.
#
# Always produces (deterministic, committed):
#   - examples/demo-media/golden-demo.captured.txt — stdout transcript
#   - examples/demo-media/golden-demo.cast         — asciinema cast built
#                                                    programmatically from
#                                                    the transcript via
#                                                    `python -m lsdf.cast_recorder`
#
# Optionally produces (uncommitted; depends on host tooling):
#   - examples/demo-media/golden-demo.gif          — rendered animated GIF
#                                                    (requires asciinema + agg)
#
# Why a deterministic cast vs a real asciinema rec:
#   the transcript is the source of truth and the demo's pass/fail report
#   is short. A programmatic cast keeps the artifact reproducible (no
#   host-prompt or terminal-styling drift); operators who want a live
#   terminal-styled GIF can run --with-gif which records via asciinema
#   first.
#
# Usage:
#   bash scripts/record-demo.sh                    # text + deterministic cast
#   bash scripts/record-demo.sh --with-gif         # also render GIF (needs
#                                                    asciinema + agg)

set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")"/.. && pwd)"
MEDIA_DIR="${REPO_ROOT}/examples/demo-media"
TXT_OUT="${MEDIA_DIR}/golden-demo.captured.txt"
CAST_OUT="${MEDIA_DIR}/golden-demo.cast"
GIF_OUT="${MEDIA_DIR}/golden-demo.gif"

WITH_GIF=0
for arg in "$@"; do
    case "$arg" in
        --with-gif)  WITH_GIF=1 ;;
        -h|--help)
            sed -n '1,/^set -euo pipefail/p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) echo "Unknown arg: $arg" >&2; exit 2 ;;
    esac
done

mkdir -p "${MEDIA_DIR}"
cd "${REPO_ROOT}"

DEMO_CMD=(docker compose --profile demo up --build
          --abort-on-container-exit --exit-code-from demo-runner demo-runner)

# 1. Always emit the deterministic stdout transcript. We strip the Docker
#    Compose build noise so the artifact stays focused on the demo's own
#    pass/fail report — the build steps are reproducible from the Dockerfile
#    and shouldn't be in the adoption-facing transcript.
echo "[record-demo] capturing demo output -> ${TXT_OUT}"
# Guard the grep with `|| true` because grep exits 1 on zero matches and
# `set -o pipefail` would otherwise abort the script — the demo command
# itself may have succeeded but Docker Compose could change its prefix
# format. We then assert the captured file is non-empty so silent format
# drift produces a clear diagnostic instead of an empty artifact.
"${DEMO_CMD[@]}" 2>&1 \
    | { grep -E '^demo-runner-1 +\| |^Container lsdf-demo|^ Container lsdf-demo' || true; } \
    > "${TXT_OUT}"
if [[ ! -s "${TXT_OUT}" ]]; then
    echo "[record-demo] ERROR: captured.txt is empty — Docker Compose output format may have changed" >&2
    echo "[record-demo] re-run the demo command directly to inspect: ${DEMO_CMD[*]}" >&2
    exit 1
fi
echo "[record-demo] wrote $(wc -l < "${TXT_OUT}") lines to ${TXT_OUT}"

# 1b. Regenerate the deterministic asciinema cast from the captured text.
#     This ships alongside captured.txt as a viewer-friendly artifact —
#     same content, replayable in asciinema-player.js or `asciinema play`.
echo "[record-demo] regenerating asciinema cast -> ${CAST_OUT}"
docker compose run --rm --entrypoint python3 cli -m lsdf.cast_recorder
echo "[record-demo] cast regenerated"

# 2. Optionally render to animated GIF via agg. Needs asciinema (to overwrite
#    the deterministic cast with a live terminal-styled one) AND agg (to
#    render). The GIF is *not* committed — it's a binary asset and the
#    deterministic cast plus captured.txt are the canonical adoption
#    artifacts.
if [[ ${WITH_GIF} -eq 1 ]]; then
    if ! command -v asciinema >/dev/null 2>&1; then
        echo "[record-demo] asciinema not installed; install via 'pipx install asciinema'" >&2
        echo "[record-demo] skipping GIF (deterministic cast still produced)" >&2
        exit 0
    fi
    if ! command -v agg >/dev/null 2>&1; then
        echo "[record-demo] agg not installed; install via 'cargo install agg'" >&2
        echo "[record-demo] skipping GIF (deterministic cast still produced)" >&2
        exit 0
    fi
    echo "[record-demo] re-recording cast with asciinema (host-styled) -> ${CAST_OUT}"
    # Wrap the docker compose invocation in `bash -c '...'` so the trailing
    # `2>&1` is interpreted as a redirect by the wrapper shell asciinema
    # spawns rather than as a literal trailing argument to the last token.
    CMD_STR="$(printf '%q ' "${DEMO_CMD[@]}")"
    asciinema rec \
        --overwrite \
        --title "LSDF Golden Demo" \
        --command "bash -c '${CMD_STR} 2>&1'" \
        "${CAST_OUT}"
    echo "[record-demo] rendering ${CAST_OUT} -> ${GIF_OUT}"
    agg "${CAST_OUT}" "${GIF_OUT}"
    echo "[record-demo] GIF written"
fi

echo "[record-demo] done"
