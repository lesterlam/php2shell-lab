#!/usr/bin/env bash
# Stage 3 walkthrough: build the instrumented php, then run each measurement mode
# against its OWN fresh worker pool.
#
# Per-mode pools for two reasons:
#
#   1. The control is only valid on a pool that has never served an OOM request.
#   2. The producer induces heap corruption, and Zend's allocator answers with
#      `zend_mm_heap corrupted` + abort(), which takes every worker down with it.
#      The process dying is a property of the thing being measured, so a crash
#      should cost one mode rather than the whole walkthrough. stage3.py reports
#      it instead of tracebacking, and each mode gets a new server here.
#
# Exits non-zero unless: the control is clean, containment is found, a length claim
# is adopted, AND an out-of-buffer read is confirmed.
#
# Usage: ./stage3.sh [--reps N] [--port N]
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
PORT="${PORT:-18627}"
REPS=3
VERSION=8.4.26
BUILD_DIR="${BUILD_DIR:-$HERE/build-instrumented}"
PHP="$BUILD_DIR/php-$VERSION/sapi/cli/php"
LOGDIR="$HERE/logs"
SRV=""

while [ $# -gt 0 ]; do
  case "$1" in
    --reps) REPS="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

mkdir -p "$LOGDIR"

cleanup() {
  if [ -n "$SRV" ]; then kill "$SRV" 2>/dev/null || true; wait "$SRV" 2>/dev/null || true; fi
}
trap cleanup EXIT

if [ ! -x "$PHP" ]; then
  echo "==> instrumented build not found, building it (a few minutes)"
  BUILD_DIR="$BUILD_DIR" "$HERE/build-instrumented.sh"
fi

start_server() {
  local log="$1"
  if (exec 3<>/dev/tcp/127.0.0.1/"$PORT") 2>/dev/null; then
    exec 3>&- || true
    echo "port $PORT is already in use -- pass --port <n>" >&2
    exit 1
  fi
  : > "$log"
  PHP_CLI_SERVER_WORKERS=4 "$PHP" -d display_errors=1 -d error_reporting=E_ALL \
    -S 127.0.0.1:"$PORT" -t "$HERE/www" 2>"$log" &
  SRV=$!
  local i
  for i in $(seq 1 40); do
    if curl -sf -m 2 "http://127.0.0.1:$PORT/diag.php" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.25
  done
  echo "server did not come up -- see $log" >&2
  exit 1
}

stop_server() {
  [ -n "$SRV" ] || return 0
  kill "$SRV" 2>/dev/null || true
  wait "$SRV" 2>/dev/null || true
  SRV=""
}

CONTROL=""; CONTAINMENT=0; CLAIM=0; LEAK=0

for mode in control containment claim leak; do
  log="$LOGDIR/instr-$mode.log"
  echo "======================================================================"
  echo "=== mode: $mode"
  echo "======================================================================"
  start_server "$log"
  out="$(python3 "$HERE/stage3.py" --port "$PORT" --log "$log" --reps "$REPS" "$mode" 2>&1)" || true
  echo "$out"
  stop_server

  probes="$(grep -c "\[INSTR-" "$log" || true)"
  echo "  ($probes probe lines in $log)"
  case "$mode" in
    control)     CONTROL="$(printf '%s\n' "$out" | grep -o 'RESULT control [A-Z]*' | awk '{print $3}' | tail -1)" ;;
    containment) CONTAINMENT="$(printf '%s\n' "$out" | grep -o 'RESULT containment [0-9]*' | awk '{print $3}' | tail -1)" ;;
    claim)       CLAIM="$(printf '%s\n' "$out" | grep -o 'RESULT claim [0-9]*' | awk '{print $3}' | tail -1)" ;;
    leak)        LEAK="$(printf '%s\n' "$out" | grep -o 'RESULT leak [0-9]*' | awk '{print $3}' | tail -1)" ;;
  esac
  echo
done

CONTROL="${CONTROL:-UNKNOWN}"
CONTAINMENT="${CONTAINMENT:-0}"
CLAIM="${CLAIM:-0}"
LEAK="${LEAK:-0}"

echo "======================================================================"
echo "VERDICT"
printf '  control clean (fresh pool, no producer) : %s\n' "$CONTROL"
printf '  containment configs found               : %s\n' "$CONTAINMENT"
printf '  length claims adopted (of %s reps)       : %s\n' "$REPS" "$CLAIM"
printf '  out-of-buffer reads confirmed           : %s\n' "$LEAK"
echo

if [ "$CONTROL" = "OK" ] && [ "$CONTAINMENT" -gt 0 ] && [ "$CLAIM" -gt 0 ] && [ "$LEAK" -gt 0 ]; then
  echo "  PASS -- content, location and timing of the corrupted memory are all under"
  echo "  attacker control: the emitted length is decoupled from the buffer it is read"
  echo "  from, and the tail is memory this request never wrote."
  exit 0
fi

echo "  FAIL -- see the mode output above; logs are in $LOGDIR" >&2
if [ "$CONTROL" = "POISONED" ]; then
  echo "  (the control ran on a pool that had already served an OOM request)" >&2
fi
exit 1
