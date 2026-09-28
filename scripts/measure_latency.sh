#!/usr/bin/env bash
# Runs N SPARK logins back to back via pamtester, printing and CSV-logging
# which transport (Bluetooth/WebSocket) each one used and how long it took.
#
# Usage: ./measure_latency.sh [N] [csv_file]
#   N        number of repetitions (default: 1)
#   csv_file output path (default: spark_latency_<timestamp>.csv)
#
# Env overrides: SPARK_PAM_SERVICE (default: authenticator-test)
#                SPARK_PAM_USER    (default: current user)
#                SPARK_GAP_SECONDS (default: 1) -- pause between runs
set -euo pipefail

N="${1:-1}"
OUT_CSV="${2:-spark_latency_$(date +%Y%m%d_%H%M%S).csv}"
SERVICE="${SPARK_PAM_SERVICE:-authenticator-test}"
PAM_USER="${SPARK_PAM_USER:-$(whoami)}"
GAP_SECONDS="${SPARK_GAP_SECONDS:-1}"
LOG_DIR="${OUT_CSV%.csv}_logs"
mkdir -p "$LOG_DIR"

echo "Running $N SPARK login(s) against PAM service '$SERVICE' as '$PAM_USER'"
echo "Approve each request on your phone when it appears."
echo

sudo -v

echo "run,transport,seconds,result" > "$OUT_CSV"

for ((i = 1; i <= N; i++)); do
    tmp_out="$(mktemp)"
    start=$(date +%s.%N)
    if sudo pamtester "$SERVICE" "$PAM_USER" authenticate > "$tmp_out" 2>&1; then
        result="OK"
    else
        result="FAILED"
    fi
    end=$(date +%s.%N)
    elapsed=$(awk -v s="$start" -v e="$end" 'BEGIN { printf "%.3f", e - s }')

    transport=$(grep -oE "Phone connected via: (Bluetooth|WebSocket)" "$tmp_out" | awk '{print $NF}' || true)
    transport="${transport:-UNKNOWN}"

    printf "Run %3d: %-10s %6ss  [%s]\n" "$i" "$transport" "$elapsed" "$result"
    echo "$i,$transport,$elapsed,$result" >> "$OUT_CSV"

    mv "$tmp_out" "$LOG_DIR/run_${i}.log"

    if ((i < N)); then
        sleep "$GAP_SECONDS"
    fi
done

echo
echo "Wrote $N run(s) to $OUT_CSV, full per-run output in $LOG_DIR/"
echo
awk -F, 'NR > 1 {
    if ($4 != "OK") { failed++; next } # excluded from the means below: not real protocol latency
    sum[$2] += $3; count[$2]++; total += $3; n++
} END {
    printf "Overall mean: %.3fs (n=%d, successful runs only)\n", total / n, n
    for (t in sum) printf "  %-10s mean %.3fs over %d run(s)\n", t, sum[t] / count[t], count[t]
    if (failed > 0) printf "%d run(s) excluded (result != OK) -- see the CSV/logs for those rows\n", failed
}' "$OUT_CSV"
