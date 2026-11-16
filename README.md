# synthetic_data_gen

Pipeline for generating synthetic vulnerability-reproduction training trajectories from
[ARVO](https://github.com/n132/ARVO) OSS-Fuzz bugs using `glm5.3-defense` behind a LiteLLM proxy.
It contains two independent generation paths that share the same task source, plus the
Kubernetes jobs used to run them at scale.

```
synthetic_data_gen/
├── exploitbench_agent/      ExploitBench agent loop (trimmed) + the ARVO MCP environment
│   ├── exploitbench/        python package: cli, runner/, contract/, db/, catalog, config
│   ├── benchmarks/
│   │   ├── bench-arvo/      ARVO adapter: Dockerfile, MCP server, shard prep, build+run scripts
│   │   └── prompts/         init-prompt templates
│   ├── testenvs/            sample-stack-bof: tiny env for `exploitbench smoke --mock-llm`
│   ├── docs/                architecture.md, decisions.md, RUNBOOK.md (upstream ExploitBench docs)
│   └── pyproject.toml       `pip install -e .` gives the `exploitbench` CLI
└── run/                     Lightweight path: static task bundles + a self-contained ReAct runner
    ├── build_synthetic_bundles.py
    ├── agent_runner_glm.py
    ├── tasks_synthetic_4631_meta.jsonl
    └── k8s/                 Job manifests for smoke and full runs
```

Shared inputs are **not** in this repo. Every script expects them at
`/projects/data/datasets/code_data/cyber_bench/run/data/`:

| File | What it is |
| --- | --- |
| `arvo.db` | SQLite dump of the ARVO table (project, fuzz target, sanitizer, crash type, crash report, fix commit, repo url) |
| `arvo_training_ids.json` | Ordered list of ARVO ids that are **not** in the 1,507-task CyberGym eval set |
| `tasks.json` | The CyberGym eval task list (used as the hold-out set) |
| `git_cache/` | Bare clones of the upstream project repos, used by `git archive` |
| `deb_cache/` | Offline apt cache mounted into the agent pods |

---

## Path A: ExploitBench agent + ARVO MCP environment (`exploitbench_agent/`)

This is the upstream [ExploitBench](https://github.com/exploitbench) runner cut down to the
pieces needed to drive an agent. Removed from upstream: the bench-v8 submodule and V8 configs,
`publish/` (HuggingFace + leaderboard), `audit/`, `api/` (FastAPI viewer), `validator/`,
`historical.py` (legacy importers), the imported V8 SQLite data, and the CLI commands that
depended on them (`publish`, `audit`, `api`, `import*`, `export`, `migrate-runs`,
`validate-image`). Everything in `runner/` is untouched.

### How one episode runs

`exploitbench benchmark --config <yaml>` expands the config into (model, env, seed) tuples and
runs them under an `asyncio.Semaphore`. For each tuple, `runner/orchestrator.py` does:

1. `runner/image_ref.py` resolves the env image to an immutable `sha256:` digest.
2. Inserts a `runs` row into SQLite (`db/schema.py`). `UNIQUE(benchmark_id, model, env_id, seed)`
   makes `--resume` a no-op for finished cells.
3. `runner/llm/factory.py` builds an LLM client from the model id prefix.
   `litellm_proxy/glm5.3-defense` selects `LiteLLMClient` and reads `LITELLM_PROXY_API_KEY` /
   `LITELLM_PROXY_API_BASE` from `.env` via `config.py`.
4. `runner/mcp_client.py` starts the env container with `docker run --network none -i <digest>`
   and speaks MCP over stdio. The container's entrypoint is the env's MCP server.
5. `runner/loop.py:run_episode` is the agent loop: enumerate MCP tools, convert them to the
   provider's tool schema (`runner/llm/tools.py`), seed the conversation with the init prompt, then
   repeat: check `Budget` (turns / weighted tokens / context), send a wrap-up or stuck nudge if due,
   call the model, write the assistant turn to `transcript.jsonl`, execute every tool call through
   MCP, and append results. A call to the tool named `grade` is parsed and its capability bitmap is
   merged into `best_caps`. The loop stops on no tool calls, budget exhaustion, `ace`, or a
   context-window error.
6. The orchestrator writes `job.json`, `score.json`, `cost.json`, `tool_calls.jsonl`,
   `grade_calls.jsonl`, and a verbatim `config_snapshot.yaml` into
   `runs/<benchmark_id>/<host>/<datetime>/<run_id>/` and marks the row `succeeded`,
   `model_failed`, or `infra_failed`.

Each run directory is a full trajectory (prompts, reasoning, tool calls, tool outputs, grade
results) and is the training-data unit for this path.

### The ARVO environment (`benchmarks/bench-arvo/`)

- `Dockerfile.arvo-mcp` layers a portable CPython 3.12 and the `mcp` package on top of
  `n132/arvo:<id>-vul`, the pre-built vulnerable OSS-Fuzz image, and sets the entrypoint to
  `mcp_server/server.py`. Bug framing is baked in as env vars: `ARVO_ID`, `ARVO_PROJECT`,
  `ARVO_FUZZ_TARGET`, `ARVO_SANITIZER`, `ARVO_CRASH_TYPE`, plus a `description.txt`.
- `mcp_server/server.py` exposes three tools:
  - `setup()` returns the task prompt (project, expected crash, fuzz target, and the ARVO crash
    report) and a `task_profile` compatible with the `rl.mcp.v8_exploit.v1` interface.
  - `exec(cmd)` runs a shell command inside the vulnerable build container.
  - `grade(path)` runs the fuzz target on the candidate input and reports
    `{crash, reached, diff}`. `crash` is true when a sanitizer signature appears in the output or
    the process dies by signal. This is the deterministic verifier.
- `prep_smoke.py` materializes three build contexts and `arvo-smoke.yaml`.
- `prep_full.py --shard-index N --shard-count 320 --total-tasks 4631` round-robins the training
  ids into shards and writes `contexts/shard-NNN/{build-<id>/, build_manifest.json, benchmark.yaml}`.
- `build_derived.py` / `shard_build_and_run.sh` pull each base image, build the derived MCP image,
  then run `exploitbench benchmark` on the shard's yaml. The shard script is what the indexed k8s
  job (`run/k8s/80-arvo-synthetic-160.yaml`) executes per pod with docker-in-docker.

### Running

```bash
cd exploitbench_agent
make install && source .venv/bin/activate
printf 'LITELLM_PROXY_API_KEY=...\nLITELLM_PROXY_API_BASE=http://<proxy>:4000/v1\n' > .env
exploitbench doctor

# no-API sanity check with the bundled sample env
bash scripts/build_sample_env.sh && exploitbench benchmark --mock-llm --test

# 3-bug ARVO smoke
python benchmarks/bench-arvo/prep_smoke.py
python benchmarks/bench-arvo/build_derived.py
exploitbench benchmark --config benchmarks/bench-arvo/arvo-smoke.yaml --turn-budget 30
exploitbench summary
```

---

## Path B: static bundles + self-contained runner (`run/`)

This path does not need per-bug Docker images. It reuses the CyberGym task-bundle format so the
same grading server can verify the PoCs.

1. `build_synthetic_bundles.py` reads `arvo.db` and `tasks.json`, drops the 1,507 eval ids, and for
   the first 4,631 remaining ARVO ids writes one bundle per task: `repo-vul.tar.gz` (a
   `git archive` of the project at `fix_commit~1`), `description.txt` (crash type, fuzz target,
   sanitizer, ASan stack), `README.md`, and `meta.json`. Repos with 15 or more tasks get full bare
   clones; the long tail uses blobless clones. `tasks_synthetic_4631_meta.jsonl` is the index of
   those bundles.
2. `agent_runner_glm.py` is a ReAct loop against an OpenAI-compatible endpoint. Per task it
   extracts the repo into an isolated non-root `/workspace`, offers `run_bash`, `read_file`,
   `write_file`, `edit_file`, and `submit_poc`, enforces offline execution, and writes
   `trace.jsonl`, `transcript.txt`, and `result.json`. Traces are also synced to Langfuse when the
   `LANGFUSE_*` env vars are set. Sharding is by `--shard-index/--shard-count` or `--only`.
3. The k8s manifests wire it up: `70-glm-smoke.yaml` (3 tasks), `75-arvo-synthetic-test20.yaml`
   (20 named tasks), `79-arvo-v2-smoke.yaml`, `81-arvo-smoke-3.yaml`, and
   `80-arvo-synthetic-160.yaml` (160 indexed pods over all 4,631 bundles). All read the LiteLLM key
   and Langfuse credentials from cluster secrets.

Submitted PoCs are graded afterwards with the CyberGym server from the eval repo, which is the
filter that decides which trajectories are kept for SFT.

## Credits

`exploitbench_agent/` is derived from ExploitBench (MIT, see `exploitbench_agent/LICENSE`).
