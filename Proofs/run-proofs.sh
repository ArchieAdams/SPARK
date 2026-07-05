#!/usr/bin/env bash
mkdir -p logs

run() {
  local script=$1
  local log="logs/${script%.sh}.log"
  bash "$script" > "$log" 2>&1
  local code=$?
  [ $code -eq 0 ] && echo "PASS  $script" || echo "FAIL  $script (exit $code, see $log)"
}

run "run-proverif-setup.sh"
run "run-proverif-remote.sh"
run "run-easycrypt.sh"

echo -e "\nSetup ProVerif:"
grep -h "^RESULT" logs/run-proverif-setup.log 2>/dev/null || echo "none found"
echo -e "\nRemote ProVerif:"
grep -h "^RESULT" logs/run-proverif-remote.log 2>/dev/null || echo "none found"