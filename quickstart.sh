#!/bin/bash

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FAIL=0

echo "=== Proofs (ProVerif + EasyCrypt, via Docker) ==="
(cd "$ROOT/Proofs" && ./run-proofs.sh) || FAIL=1

echo
echo "=== PAM (build + unit tests, via Docker) ==="
docker build -t spark-pam -f "$ROOT/PAM/PAM.dockerfile" "$ROOT/PAM" && docker run --rm spark-pam || FAIL=1

echo
if [ "$FAIL" -eq 0 ]; then
    echo "Quick start: PASS"
else
    echo "Quick start: FAIL (see output above)"
fi
exit "$FAIL"
