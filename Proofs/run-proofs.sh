#!/usr/bin/env bash
mkdir -p logs
FAIL=0

run() {
  local script=$1
  local log="logs/${script%.sh}.log"
  bash "$script" > "$log" 2>&1
  local code=$?
  if [ $code -eq 0 ]; then
    echo "PASS  $script"
  else
    echo "FAIL  $script (exit $code, see $log)"
    FAIL=1
  fi
}

run "run-proverif-pair-v2.sh"
run "run-proverif-pair-v1.sh"
run "run-proverif-auth.sh"
run "run-proverif-full.sh"
run "run-easycrypt.sh"

echo -e "\nPairing v2 (two-nonce SAS, expect all queries true):"
grep -h "^RESULT" logs/run-proverif-pair-v2.log 2>/dev/null || echo "none found"
echo -e "\nPairing v1 (single-nonce SAS, expect 'is false' -- this is the attack, not a tool failure):"
grep -h "^RESULT" logs/run-proverif-pair-v1.log 2>/dev/null || echo "none found"
echo -e "\nAuthentication:"
grep -h "^RESULT" logs/run-proverif-auth.log 2>/dev/null || echo "none found"
echo -e "\nFull composition (pairing v2 + authentication):"
grep -h "^RESULT" logs/run-proverif-full.log 2>/dev/null || echo "none found"
echo -e "\nEasyCrypt:"
grep -hE "^(Clean pass|WARNING|FAILED|Exit code)" logs/run-easycrypt.log 2>/dev/null || echo "none found"

exit "$FAIL"