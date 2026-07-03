#!/usr/bin/env bash
mkdir -p logs

run() {
  local script=$1
  local log="logs/${script%.sh}.log"
  bash "$script" > "$log" 2>&1
  local code=$?
  [ $code -eq 0 ] && echo "PASS  $script" || echo "FAIL  $script (exit $code, see $log)"
}

run "setup-proverif.sh"
run "remote-proverif.sh"
run "run-easycrypt.sh"

echo -e "\nSetup ProVerif:"
grep -h "^RESULT" logs/setup-proverif.log 2>/dev/null || echo "none found"
echo -e "\nRemote ProVerif:"
grep -h "^RESULT" logs/remote-proverif.log 2>/dev/null || echo "none found"