#!/bin/bash

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FAIL=0

echo "=== Proofs (ProVerif + EasyCrypt, via Docker) ==="
(cd "$ROOT/Proofs" && ./run-proofs.sh) || FAIL=1

echo
echo "=== PAM (build + unit tests) ==="
(cd "$ROOT/PAM" && ./build_pam.sh) || FAIL=1
(cd "$ROOT/PAM" && ctest --test-dir build --output-on-failure) || FAIL=1

echo
if [ "$FAIL" -eq 0 ]; then
    echo "Quick start: PASS"
else
    echo "Quick start: FAIL (see output above)"
fi
exit "$FAIL"
