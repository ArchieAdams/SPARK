# Evaluation

Login latency measurements behind §5.3 / Fig. 4.

Needs a PC paired with a real Android phone (§4.2), so results won't be
bit-for-bit reproducible, a rerun will reflect your own phone and radio
conditions, not necessarily the exact numbers here. Excluded from the AE
badge claims for the same reason (see `AE.md`).

## Prerequisites

- PAM module built and installed, phone already paired (`PAM/pam_config/`).
- `pamtester`, with a PAM service configured to call `pam_authenticator.so`
  (the repo ships `authenticator-test`).
- Phone reachable over both Bluetooth and Wi-Fi/LAN.

## Running it

```
sudo ./scripts/measure_latency.sh 20 evaluation/results/my_run.csv
```

Approve each request on the phone. Outputs a CSV
(`run,transport,seconds,result`) and a `my_run_logs/` directory with the
full PAM log per run. See the script's header comment for options
(`SPARK_GAP_SECONDS`, `SPARK_PAM_SERVICE`, `SPARK_PAM_USER`).

Scenarios:

- **Parallel channels** (default): both interfaces up, run as above.
- **Bluetooth-only**: disable Wi-Fi first, then run the same command.
- **WebSocket-only**: disable Bluetooth first, then run the same command.

## `results/`

| File | Condition | n |
|---|---|---|
| `BT.csv` | Bluetooth-only (Wi-Fi disabled) | 20 |
| `WS.csv` | Dual-race sweep, WebSocket won every attempt | 20 |
| `Race.csv` | Dual-race sweep, both interfaces enabled (16 Bluetooth / 4 WebSocket wins) | 20 |

`result != OK` rows are failed/interrupted runs, excluded from any
mean/variance. `BT.csv` run 1 (4007 ms) and `Race.csv` run 1 (4247 ms) are
the first Bluetooth connection of their session, paying a one-off radio
re-page cost — not measurement error.
