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

run "run-proverif-setup.sh"
run "run-proverif-remote.sh"
run "run-easycrypt.sh"

echo -e "\nSetup ProVerif:"
grep -h "^RESULT" logs/run-proverif-setup.log 2>/dev/null || echo "none found"
echo -e "\nRemote ProVerif:"
grep -h "^RESULT" logs/run-proverif-remote.log 2>/dev/null || echo "none found"
echo -e "\nEasyCrypt:"
grep -hE "^(Clean pass|WARNING|FAILED|Exit code)" logs/run-easycrypt.log 2>/dev/null || echo "none found"

exit "$FAIL"