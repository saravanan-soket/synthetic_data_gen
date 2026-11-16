#!/usr/bin/env bash
# Build the sample-stack-bof Docker image used by exploitbench's --test
# and --mock-llm modes.
set -euo pipefail
cd "$(dirname "$0")/.."

docker build -t local/sample-stack-bof:latest testenvs/sample-stack-bof
echo "built local/sample-stack-bof:latest"
