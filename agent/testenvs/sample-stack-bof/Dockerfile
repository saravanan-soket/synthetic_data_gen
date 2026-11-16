# Sample env: a tiny stack-buffer-overflow target with a Python MCP server.
# Build-from-scratch is seconds, not hours — drives exploitbench's --test and
# --mock-llm modes without dragging in V8.

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        libc-dev \
        python3 \
        python3-pip \
        python3-venv \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install MCP server deps in a venv (Debian 12 enforces PEP 668).
RUN python3 -m venv /opt/mcp_venv \
    && /opt/mcp_venv/bin/pip install --no-cache-dir mcp>=1.1

# Build the vulnerable binary.
RUN mkdir -p /rlenv/binaries/vuln /rlenv/workspace /rlenv/problem /rlenv/mcp
COPY src/bof.c /tmp/bof.c
RUN gcc -O0 -fno-stack-protector -no-pie -o /rlenv/binaries/vuln/bof /tmp/bof.c \
    && chmod +x /rlenv/binaries/vuln/bof \
    && rm /tmp/bof.c

COPY problem/ /rlenv/problem/
COPY mcp_server/server.py /rlenv/mcp/server.py
RUN chmod 755 /rlenv/workspace

# Drop privileges before serving the model — matches vr-agent's posture.
RUN useradd --uid 1000 --create-home --shell /bin/bash agent \
    && chown -R agent:agent /rlenv/workspace
USER agent

ENV RLENV_PROBLEM_DIR=/rlenv/problem \
    RLENV_WORKSPACE_DIR=/rlenv/workspace \
    RLENV_VULN_BINARY=/rlenv/binaries/vuln/bof \
    PATH=/opt/mcp_venv/bin:$PATH

ENTRYPOINT ["/opt/mcp_venv/bin/python", "/rlenv/mcp/server.py"]
