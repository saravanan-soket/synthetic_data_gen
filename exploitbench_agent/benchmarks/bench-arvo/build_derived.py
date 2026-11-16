#!/usr/bin/env python3
"""Build the derived MCP images for every env in the smoke manifest."""
import json, subprocess, sys, pathlib
BA = pathlib.Path(__file__).parent
envs = json.load(open(BA / "smoke_build_manifest.json"))
rc_all = 0
for e in envs:
    lid = e["id"].split("-", 1)[1]
    tar_path = BA.parent.parent / "data" / f"arvo-{lid}.tar"
    if tar_path.exists():
        print(f">> loading pre-built {e['image']} from {tar_path}", flush=True)
        r = subprocess.run(["docker", "load", "-i", str(tar_path)])
        print(f"   load rc={r.returncode}", flush=True)
        rc_all |= r.returncode
        continue

    ctx = BA / f"build-{lid}"
    print(f">> pull {e['_base']}", flush=True)
    subprocess.run(["docker", "pull", e["_base"]], check=False)
    print(f">> build {e['image']} (ctx={ctx})", flush=True)
    r = subprocess.run(
        ["docker", "build", "-t", e["image"],
         "--build-arg", f"ARVO_BASE={e['_base']}",
         "--build-arg", f"ARVO_ID={lid}",
         "--build-arg", f"ARVO_PROJECT={e['_project']}",
         "--build-arg", f"ARVO_FUZZ_TARGET={e['_fuzz_target']}",
         "--build-arg", f"ARVO_SANITIZER={e['_sanitizer']}",
         "--build-arg", f"ARVO_CRASH_TYPE={e['_crash_type']}",
         str(ctx)],
        cwd=str(ctx))
    print(f"   build rc={r.returncode}", flush=True)
    rc_all |= r.returncode
sys.exit(1 if rc_all else 0)
