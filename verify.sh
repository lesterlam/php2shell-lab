#!/usr/bin/env bash
#
# Non-interactive gate: assert that the vulnerable build triggers and the
# patched build does not. Exits 0 only if both hold.
#
#   ./fetch-php.sh 8.4.26 && ./fetch-php.sh 8.4.27 && ./verify.sh
#
set -uo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

VP=8626      # vulnerable PHP
PP=8627      # patched PHP
MEM=64M
PMS=256M
HEADERS=250000

V_PID=""; P_PID=""
cleanup() { [ -n "$V_PID" ] && kill "$V_PID" 2>/dev/null; [ -n "$P_PID" ] && kill "$P_PID" 2>/dev/null; }
trap cleanup EXIT

./phpv.sh 8.4.26 -d memory_limit=$MEM -d post_max_size=$PMS -d display_errors=1 \
  -d error_reporting=E_ALL -S "127.0.0.1:$VP" -t www >/dev/null 2>&1 & V_PID=$!
./phpv.sh 8.4.27 -d memory_limit=$MEM -d post_max_size=$PMS -d display_errors=1 \
  -d error_reporting=E_ALL -S "127.0.0.1:$PP" -t www >/dev/null 2>&1 & P_PID=$!
sleep 2

vout=$(python3 probe.py --port "$VP" --headers "$HEADERS" 2>&1)
pout=$(python3 probe.py --port "$PP" --headers "$HEADERS" 2>&1)

echo "=== vulnerable PHP 8.4.26 ==="; echo "$vout"
echo
echo "=== patched PHP 8.4.27 ==="; echo "$pout"
echo

fail=0
if echo "$vout" | grep -q 'TRIGGERED'; then
  echo "PASS  vulnerable build triggers on a $HEADERS-header body"
else
  echo "FAIL  vulnerable build did NOT trigger (expected OOM before app code)"; fail=1
fi

if echo "$pout" | grep -q 'APP REACHED'; then
  echo "PASS  patched build parses the same body normally"
else
  echo "FAIL  patched build did not reach the application"; fail=1
fi

if echo "$pout" | grep -q 'TRIGGERED'; then
  echo "FAIL  patched build triggered -- regression, or the wrong runtime was fetched"; fail=1
else
  echo "PASS  patched build does not trigger"
fi

echo
if [ "$fail" -eq 0 ]; then
  echo "RESULT: PASS"
else
  echo "RESULT: FAIL"
fi
exit "$fail"
