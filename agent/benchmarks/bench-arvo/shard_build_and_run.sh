#!/bin/bash
# Per-shard: materialize contexts, build derived images, run ExploitBench.
set -uo pipefail
IDX=${JOB_COMPLETION_INDEX:-0}
SHARD_COUNT=${SHARD_COUNT:-320}
ROOT=/projects/data/datasets/code_data/cyber_bench/synthetic_data_gen/agent
BA=$ROOT/benchmarks/bench-arvo
SHARD=$(printf "shard-%03d" "$IDX")
OUT=$ROOT/runs_arvo_full/$SHARD
mkdir -p "$OUT"
LOG=$OUT/log.txt
exec > >(tee -a "$LOG") 2>&1
echo "=== shard=$IDX start $(date -u +%FT%TZ) ==="
# fetch docker-cli
curl -fsSL https://download.docker.com/linux/static/stable/x86_64/docker-27.5.1.tgz | tar xz -C /tmp docker/docker
install /tmp/docker/docker /usr/local/bin/docker
until docker info >/dev/null 2>&1; do echo "wait dind"; sleep 3; done
# materialize this shard's contexts
python3 $BA/prep_full.py --shard-index "$IDX" --shard-count "$SHARD_COUNT" --total-tasks "${TOTAL_TASKS:-6138}"
# build derived MCP images for every bug in this shard
python3 - <<'PY'
import json, os, subprocess, sys
IDX = int(os.environ.get("JOB_COMPLETION_INDEX", "0"))
BA = "/projects/data/datasets/code_data/cyber_bench/synthetic_data_gen/agent/benchmarks/bench-arvo"
manifest = json.load(open(f"{BA}/contexts/shard-{IDX:03d}/build_manifest.json"))
rc_all = 0
for e in manifest:
    lid = e["id"].split("-", 1)[1]
    ctx = f"{BA}/contexts/shard-{IDX:03d}/build-{lid}"
    print(f">> pull {e['_base']}", flush=True)
    r = subprocess.run(["docker", "pull", e["_base"]])
    if r.returncode:
        print(f"   PULL FAILED {e['_base']}", flush=True); rc_all |= 1; continue
    print(f">> build {e['image']}", flush=True)
    r = subprocess.run(
        ["docker", "build", "-t", e["image"],
         "--build-arg", f"ARVO_BASE={e['_base']}",
         "--build-arg", f"ARVO_ID={lid}",
         "--build-arg", f"ARVO_PROJECT={e['_project']}",
         "--build-arg", f"ARVO_FUZZ_TARGET={e['_fuzz_target']}",
         "--build-arg", f"ARVO_SANITIZER={e['_sanitizer']}",
         "--build-arg", f"ARVO_CRASH_TYPE={e['_crash_type']}",
         ctx], cwd=ctx)
    print(f"   build rc={r.returncode}", flush=True)
    if r.returncode: rc_all |= 1
    # free base-image disk promptly
    subprocess.run(["docker", "rmi", e["_base"]], check=False)
print(f"BUILDS DONE (any_fail={rc_all})", flush=True)
PY
# install exploitbench and run
echo "--- install exploitbench ---"
cd "$ROOT" && pip install -q -e . 2>&1 | tail -5
echo "--- run benchmark ---"
export EXPLOITBENCH_RUNS_DIR=$OUT/runs
exploitbench benchmark --config $BA/contexts/$SHARD/benchmark.yaml 2>&1 | tail -400
echo "=== shard=$IDX done $(date -u +%FT%TZ) ==="
