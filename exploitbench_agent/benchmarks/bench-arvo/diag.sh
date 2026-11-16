#!/bin/bash
set -uo pipefail
IMG=n132/arvo:40096184-vul
echo "=== pulling $IMG ==="
docker pull "$IMG" 2>&1 | tail -3
echo "=== base OS + python availability ==="
docker run --rm --entrypoint sh "$IMG" -c 'cat /etc/os-release 2>/dev/null | head -2; echo "---python:"; which python3 python 2>/dev/null; python3 --version 2>&1; echo "---pip:"; which pip3 pip 2>/dev/null; echo "---apt sources alive:"; (apt-get update -qq 2>&1 | tail -2) || echo "apt FAILED"; echo "---fuzz target location:"; ls -la /out/ 2>/dev/null | head; echo "---arvo cmd:"; which arvo; file /out/* 2>/dev/null | head -3'
echo "=== DIAG DONE ==="
