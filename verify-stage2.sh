#!/usr/bin/env bash
#
# Non-interactive stage-2 gate. Exits 0 only if all four hold:
#
#   1. a fresh vulnerable worker returns ordinary 32-byte ids   (control)
#   2. after one OOM, the vulnerable worker leaks stale memory  (the bug)
#   3. a fresh patched worker returns ordinary ids              (control)
#   4. after the same payload, the patched worker does not      (the fix)
#
# Conditions 1 and 3 matter as much as 2 and 4: without them, "the follow-up
# looks wrong" could just be a shape that misbehaves on any build.
#
#   ./fetch-php.sh 8.4.26 fpm-alpine3.23
#   ./fetch-php.sh 8.4.27 fpm-alpine3.23
#   ./verify-stage2.sh
#
set -uo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

VP=8626                 # vulnerable
PP=8627                 # patched
RUN_V=8.4.26-fpm-alpine3.23
RUN_P=8.4.27-fpm-alpine3.23
MEM=128M
WORKERS=4
REPS=20

V_PID=""; P_PID=""
cleanup() { [ -n "$V_PID" ] && kill "$V_PID" 2>/dev/null; [ -n "$P_PID" ] && kill "$P_PID" 2>/dev/null; }
trap cleanup EXIT

serve() { PHP_CLI_SERVER_WORKERS=$WORKERS ./phpv.sh "$1" -d memory_limit=$MEM \
            -d display_errors=1 -d error_reporting=E_ALL -S "127.0.0.1:$2" -t www \
            >/dev/null 2>&1 & }

wait_up() {
  for _ in $(seq 1 40); do
    curl -sf -m 2 "http://127.0.0.1:$1/diag.php" >/dev/null 2>&1 && return 0
    sleep 0.5
  done
  return 1
}

for r in "$RUN_V" "$RUN_P"; do
  ./phpv.sh "$r" -v >/dev/null 2>&1 || {
    echo "missing runtime $r -- run: ./fetch-php.sh ${r%%-*} fpm-alpine3.23" >&2
    exit 1
  }
done

serve "$RUN_V" $VP; V_PID=$!
serve "$RUN_P" $PP; P_PID=$!
wait_up $VP || { echo "vulnerable server did not come up" >&2; exit 1; }
wait_up $PP || { echo "patched server did not come up" >&2; exit 1; }

# Control first: these servers must be clean before anything OOMs them.
v_fresh=$(python3 stage2.py --port $VP fresh --reps 8 2>&1)
p_fresh=$(python3 stage2.py --port $PP fresh --reps 8 2>&1)
v_after=$(python3 stage2.py --port $VP after --reps $REPS 2>&1)
p_after=$(python3 stage2.py --port $PP after --reps $REPS 2>&1)

echo "=== 1. control: fresh vulnerable worker ==="; echo "$v_fresh"
echo; echo "=== 2. after one OOM: vulnerable worker ==="; echo "$v_after"
echo; echo "=== 3. control: fresh patched worker ==="; echo "$p_fresh"
echo; echo "=== 4. after the same payload: patched worker ==="; echo "$p_after"
echo

fail=0
if grep -q 'CLEAN' <<<"$v_fresh"; then
  echo "PASS  fresh vulnerable worker returns ordinary 32-byte ids"
else
  echo "FAIL  fresh vulnerable worker was not clean -- control broken, results unreliable"
  fail=1
fi

if grep -q 'ANOMALY' <<<"$v_after"; then
  echo "PASS  after an OOM, the vulnerable worker leaks stale state"
else
  echo "FAIL  no anomaly on the vulnerable build after an OOM"
  fail=1
fi

if grep -q 'CLEAN' <<<"$p_fresh"; then
  echo "PASS  fresh patched worker returns ordinary 32-byte ids"
else
  echo "FAIL  patched worker was not clean"
  fail=1
fi

if grep -q 'ANOMALY' <<<"$p_after"; then
  echo "FAIL  patched build showed an anomaly -- regression, or the wrong runtime was fetched"
  fail=1
else
  echo "PASS  patched build shows no anomaly after the same payload"
fi

echo
if [ "$fail" -eq 0 ]; then echo "RESULT: PASS"; else echo "RESULT: FAIL"; fi
exit "$fail"
