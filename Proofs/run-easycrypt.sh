[ -n "$SPARK_SKIP_DOCKER_BUILD" ] || docker build -f Easycrypt.dockerfile -t easycrypt .

docker run --rm -v "$(pwd)":/artifact easycrypt ./HashCommit.ec 2>&1 | tee output.log
EXIT_CODE=${PIPESTATUS[0]}
echo "Exit code: $EXIT_CODE"

if [ "$EXIT_CODE" -eq 0 ] && ! grep -qE "Error|error|Fail|fail|Exception|exception" output.log; then
  echo "Clean pass"
  exit 0
elif [ "$EXIT_CODE" -eq 0 ]; then
  echo "WARNING: exit 0 but suspicious text found"
  exit 1
else
  echo "FAILED — see output.log"
  exit "$EXIT_CODE"
fi