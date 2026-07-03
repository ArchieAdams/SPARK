docker build -f Easycrypt.dockerfile -t easycrypt .

docker run --rm -v "$(pwd)":/artifact easycrypt ./HashCommit.ec 2>&1 | tee output.log
EXIT_CODE=${PIPESTATUS[0]}
echo "Exit code: $EXIT_CODE"

if [ "$EXIT_CODE" -eq 0 ]; then
  grep -qE "Error|error|Fail|fail|Exception|exception" output.log && echo "WARNING: exit 0 but suspicious text found" || echo "Clean pass"
else
  echo "FAILED — see output.log"
fi